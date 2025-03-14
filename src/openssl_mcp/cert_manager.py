import os
import tempfile
import logging
from typing import Dict, Any, Optional, List
from .response import ResponseWrapper, SuccessResponse, ErrorResponse, ResponseType
from .utils import run_openssl_command, is_safe_path
from .openssl_models import KeyPairConfig, CertificateConfig, CRLConfig, OCSPConfig
from .openssl_command import OpenSSLCommandBuilder
from pydantic import BaseModel

class CertificateManager(BaseModel):
    working_dir: str
    certs_dir: str
    keys_dir: str
    crl_dir: str
    ocsp_dir: str

    def __init__(self, working_dir: str):
        """Initialize CertificateManager with working directory.
        
        Args:
            working_dir: Base directory for all certificate operations
        """
        super().__init__(
            working_dir=working_dir,
            certs_dir=os.path.join(working_dir, "certificates"),
            keys_dir=os.path.join(working_dir, "keys"),
            crl_dir=os.path.join(working_dir, "crl"),
            ocsp_dir=os.path.join(working_dir, "ocsp")
        )
        
        # Create directories if they don't exist
        for directory in [self.certs_dir, self.keys_dir, self.crl_dir, self.ocsp_dir]:
            os.makedirs(directory, exist_ok=True)
    
    def generate_key_pair(self, key_name: str, key_type: str = "rsa", key_size: int = 2048) -> ResponseType:
        """Generate a new key pair (private and public keys).
        
        Args:
            key_name: Name for the key pair
            key_type: Type of key to generate (rsa, dsa, or ec)
            key_size: Size of the key in bits
            
        Returns:
            Dictionary containing the operation result
        """
        try:
            config = KeyPairConfig(
                key_name=key_name,
                key_type=key_type,
                key_size=key_size
            )
        except ValueError as e:
            return ResponseWrapper.error_response(str(e))
        
        # Set file paths
        private_key_path = os.path.join(self.keys_dir, f"{config.key_name}.key")
        public_key_path = os.path.join(self.keys_dir, f"{config.key_name}.pub")
        
        # Check if files already exist
        if os.path.exists(private_key_path) or os.path.exists(public_key_path):
            return ResponseWrapper.error_response(f"Key with name {config.key_name} already exists")
        
        # Generate private key
        command = OpenSSLCommandBuilder.build_key_pair_command(config, self.working_dir)
        result = run_openssl_command(command.args)
        if not result.success:
            return result
        
        # Extract public key from private key
        pub_command = OpenSSLCommandBuilder.build_extract_public_key_command(
            private_key_path=private_key_path,
            public_key_path=public_key_path
        )
        
        pub_result = run_openssl_command(pub_command.args)
        if not pub_result.success:
            # Clean up private key if public key generation fails
            os.remove(private_key_path)
            return pub_result
        
        return ResponseWrapper.success_response(
            f"Generated {config.key_type.upper()} key pair: {config.key_name}",
            {
                "private_key": os.path.relpath(private_key_path, self.working_dir),
                "public_key": os.path.relpath(public_key_path, self.working_dir)
            }
        )
    
    def create_certificate(self, key_name: str, common_name: str, days: int = 365,
                          cert_name: Optional[str] = None, is_ca: bool = False) -> ResponseType:
        """Create a certificate using an existing key pair.
        
        Args:
            key_name: Name of the key pair to use
            common_name: Common Name (CN) for the certificate
            days: Validity period in days
            cert_name: Optional name for the certificate (defaults to key_name)
            is_ca: Whether this is a CA certificate
            
        Returns:
            Dictionary containing the operation result
        """
        try:
            config = CertificateConfig(
                key_name=key_name,
                common_name=common_name,
                days=days,
                cert_name=cert_name,
                is_ca=is_ca
            )
        except ValueError as e:
            return ResponseWrapper.error_response(str(e))
        
        # Set file paths
        private_key_path = os.path.join(self.keys_dir, f"{config.key_name}.key")
        cert_path = os.path.join(self.certs_dir, f"{config.cert_name or config.key_name}.crt")
        
        # Check if private key exists
        if not os.path.exists(private_key_path):
            return ResponseWrapper.error_response(f"Private key {config.key_name}.key does not exist")
        
        # Check if certificate already exists
        if os.path.exists(cert_path):
            return ResponseWrapper.error_response(f"Certificate {config.cert_name or config.key_name}.crt already exists")
        
        # Create a temporary config file for certificate details
        with tempfile.NamedTemporaryFile(mode='w', delete=True) as config_file:
            config_file.write(f'''
[req]
distinguished_name=req_distinguished_name
x509_extensions={"v3_ca" if config.is_ca else "v3_req"}
prompt=no

[req_distinguished_name]
CN={config.common_name}

[v3_req]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
extendedKeyUsage=clientAuth, serverAuth
authorityInfoAccess=OCSP;URI:http://ocsp.example.com

[v3_ca]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints=critical,CA:true
keyUsage=critical,digitalSignature,cRLSign,keyCertSign
authorityInfoAccess=OCSP;URI:http://ocsp.example.com
''')
            config_path = config_file.name
        
        try:
            # Create certificate
            command = OpenSSLCommandBuilder.build_certificate_command(
                config=config,
                working_dir=self.working_dir,
                config_path=config_path
            )
            
            result = run_openssl_command(command.args)
            if not result.success:
                return result
            
            return ResponseWrapper.success_response(
                f"Created {'CA' if config.is_ca else ''} certificate: {config.cert_name or config.key_name}",
                {"certificate": os.path.relpath(cert_path, self.working_dir)}
            )
        finally:
            if os.path.exists(config_path):
                try:
                    os.unlink(config_path)
                except Exception as e:
                    logging.error(f"Failed to clean up temp file: {e}")
    
    def create_crl(self, ca_key: str, ca_cert: str, serial_numbers: List[str],
                   days: int = 30, crl_name: str = None) -> ResponseType:
        """Create a Certificate Revocation List (CRL).
        
        Args:
            ca_key: Name of the CA private key
            ca_cert: Name of the CA certificate
            serial_numbers: List of certificate serial numbers to revoke
            days: Validity period for the CRL in days
            crl_name: Optional name for the CRL (defaults to ca_cert)
            
        Returns:
            Dictionary containing the operation result
        """
        try:
            config = CRLConfig(
                ca_key=ca_key,
                ca_cert=ca_cert,
                serial_numbers=serial_numbers,
                days=days,
                crl_name=crl_name
            )
        except ValueError as e:
            return ResponseWrapper.error_response(str(e))
        
        # Set file paths
        ca_key_path = os.path.join(self.keys_dir, f"{config.ca_key}.key")
        ca_cert_path = os.path.join(self.certs_dir, f"{config.ca_cert}.crt")
        crl_path = os.path.join(self.crl_dir, f"{config.crl_name or config.ca_cert}.crl")
        
        # Check if required files exist
        if not os.path.exists(ca_key_path):
            return ResponseWrapper.error_response(f"CA private key {config.ca_key}.key does not exist")
        if not os.path.exists(ca_cert_path):
            return ResponseWrapper.error_response(f"CA certificate {config.ca_cert}.crt does not exist")
        
        # Create a temporary file for serial numbers
        with tempfile.NamedTemporaryFile(mode='w', delete=True) as serial_file:
            for serial in config.serial_numbers:
                serial_file.write(f"{serial}\n")
            serial_file.flush()
            serial_path = serial_file.name
            
            # Create CRL
            command = OpenSSLCommandBuilder.build_crl_command(
                config=config,
                working_dir=self.working_dir,
                serial_path=serial_path
            )
            
            result = run_openssl_command(command.args)
            if not result.success:
                return result
            
            return ResponseWrapper.success_response(
                f"Created CRL: {config.crl_name or config.ca_cert}",
                {"crl": os.path.relpath(crl_path, self.working_dir)}
            )
    
    def create_ocsp_response(self, ca_key: str, ca_cert: str, cert_name: str,
                            status: str = "good", revocation_time: str = None,
                            revocation_reason: int = None) -> ResponseType:
        """Create an OCSP response for a certificate.
        
        Args:
            ca_key: Name of the CA private key
            ca_cert: Name of the CA certificate
            cert_name: Name of the certificate to create response for
            status: Certificate status (good, revoked, or unknown)
            revocation_time: Time of revocation (required if status is revoked)
            revocation_reason: Reason code for revocation (0-10, required if status is revoked)
            
        Returns:
            Dictionary containing the operation result
        """
        try:
            config = OCSPConfig(
                ca_key=ca_key,
                ca_cert=ca_cert,
                cert_name=cert_name,
                status=status,
                revocation_time=revocation_time,
                revocation_reason=revocation_reason
            )
        except ValueError as e:
            return ResponseWrapper.error_response(str(e))
        
        # Set file paths
        ca_key_path = os.path.join(self.keys_dir, f"{config.ca_key}.key")
        ca_cert_path = os.path.join(self.certs_dir, f"{config.ca_cert}.crt")
        cert_path = os.path.join(self.certs_dir, f"{config.cert_name}.crt")
        
        # Check if required files exist
        if not os.path.exists(ca_key_path):
            return ResponseWrapper.error_response(f"CA private key {config.ca_key}.key does not exist")
        if not os.path.exists(ca_cert_path):
            return ResponseWrapper.error_response(f"CA certificate {config.ca_cert}.crt does not exist")
        if not os.path.exists(cert_path):
            return ResponseWrapper.error_response(f"Certificate {config.cert_name}.crt does not exist")
        
        # Create OCSP response
        command = OpenSSLCommandBuilder.build_ocsp_command(
            config=config,
            working_dir=self.working_dir
        )
        
        result = run_openssl_command(command.args)
        if not result.success:
            return result
        
        return ResponseWrapper.success_response(
            f"Created OCSP response for certificate: {config.cert_name}",
            {"status": config.status}
        )