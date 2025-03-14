import os
import base64
import tempfile
from typing import Dict, Any, Optional, List
from response import ResponseWrapper
from utils import run_openssl_command, is_safe_path

class CryptoManager:
    def __init__(self, working_dir: str):
        """Initialize CryptoManager with working directory.
        
        Args:
            working_dir: Base directory for all crypto operations
        """
        self.working_dir = working_dir
        self.certs_dir = os.path.join(working_dir, "certificates")
        self.keys_dir = os.path.join(working_dir, "keys")
        self.files_dir = os.path.join(working_dir, "files")
        
        # Create directories if they don't exist
        for directory in [self.certs_dir, self.keys_dir, self.files_dir]:
            os.makedirs(directory, exist_ok=True)
    
    def export_pkcs12(self, key_name: str, cert_name: str = None, password: str = None) -> Dict[str, Any]:
        """Export certificate and private key to PKCS12 format.
        
        Args:
            key_name: Name of the key pair
            cert_name: Optional name for the certificate (defaults to key_name)
            password: Optional password for the PKCS12 file
            
        Returns:
            Dictionary containing the operation result
        """
        key_name = key_name.strip()
        if cert_name is None:
            cert_name = key_name
        cert_name = cert_name.strip()
        
        # Validate parameters
        if not key_name:
            return ResponseWrapper.error_response("Key name cannot be empty")
        
        # Set file paths
        private_key_path = os.path.join(self.keys_dir, f"{key_name}.key")
        cert_path = os.path.join(self.certs_dir, f"{cert_name}.crt")
        pkcs12_path = os.path.join(self.files_dir, f"{key_name}.p12")
        
        # Check if files exist
        if not os.path.exists(private_key_path):
            return ResponseWrapper.error_response(f"Private key {key_name}.key does not exist")
        if not os.path.exists(cert_path):
            return ResponseWrapper.error_response(f"Certificate {cert_name}.crt does not exist")
        
        # Create PKCS12 file
        command = [
            "openssl", "pkcs12",
            "-export",
            "-in", cert_path,
            "-inkey", private_key_path,
            "-out", pkcs12_path,
        ]
        
        if password:
            command.extend(["-password", f"pass:{password}"])
        else:
            command.extend(["-nodes"])
        
        result = run_openssl_command(command)
        if not result["success"]:
            return result
        
        return ResponseWrapper.success_response(
            f"Exported certificate and private key to {os.path.basename(pkcs12_path)}",
            {"pkcs12_file": os.path.relpath(pkcs12_path, self.working_dir)}
        )
    
    def get_supported_ciphers(self) -> Dict[str, Any]:
        """Get a list of supported FIPS-compliant ciphers.
        
        Returns:
            Dictionary containing the list of supported ciphers
        """
        command = ["openssl", "list", "-cipher-algorithms"]
        result = run_openssl_command(command)
        if not result["success"]:
            return result
        
        # Filter for FIPS-compliant ciphers
        fips_ciphers = [
            "aes-128-gcm",
            "aes-192-gcm",
            "aes-256-gcm",
            "aes-128-ccm",
            "aes-192-ccm",
            "aes-256-ccm"
        ]
        
        return ResponseWrapper.success_response(
            "Retrieved supported FIPS-compliant ciphers",
            {"ciphers": fips_ciphers}
        )
    
    def encrypt_file(self, input_path: str, recipient_cert: str, output_path: str, cipher: str = "aes-256-gcm") -> Dict[str, Any]:
        """Encrypt a file using a recipient's certificate and FIPS-compliant cipher.
        
        Args:
            input_path: Path to the file to encrypt
            recipient_cert: Name of the recipient's certificate
            output_path: Path where to save the encrypted file
            cipher: FIPS-compliant cipher to use (default: aes-256-gcm)
            
        Returns:
            Dictionary containing the operation result
        """
        input_path = input_path.strip()
        recipient_cert = recipient_cert.strip()
        output_path = output_path.strip()
        cipher = cipher.strip().lower()
        
        # Validate parameters
        if not input_path or not recipient_cert or not output_path:
            return ResponseWrapper.error_response(
                "Input path, recipient certificate, and output path cannot be empty")
        
        # Validate cipher
        supported_ciphers = self.get_supported_ciphers()
        if not supported_ciphers["success"]:
            return supported_ciphers
        
        if cipher not in supported_ciphers["data"]["ciphers"]:
            return ResponseWrapper.error_response(
                f"Unsupported cipher: {cipher}. Please use a FIPS-compliant cipher.")
        
        # Set file paths
        full_input_path = os.path.join(self.files_dir, input_path)
        cert_path = os.path.join(self.certs_dir, f"{recipient_cert}.crt")
        full_output_path = os.path.join(self.files_dir, output_path)
        
        # Check paths are safe
        if not is_safe_path(self.working_dir, full_input_path) or \
           not is_safe_path(self.working_dir, full_output_path):
            return ResponseWrapper.error_response("Path outside working directory not allowed")
        
        # Check if files exist and are readable
        try:
            if not os.path.exists(full_input_path):
                return ResponseWrapper.error_response(f"Input file {input_path} does not exist")
            if not os.access(full_input_path, os.R_OK):
                return ResponseWrapper.error_response(f"Input file {input_path} is not readable")
            if not os.path.exists(cert_path):
                return ResponseWrapper.error_response(f"Certificate {recipient_cert}.crt does not exist")
        except Exception as e:
            return ResponseWrapper.error_response(f"Error checking file access: {str(e)}")
        
        # Extract public key from certificate to a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_pubkey:
            pubkey_path = temp_pubkey.name
        
        try:
            # Extract public key
            extract_command = [
                "openssl", "x509",
                "-in", cert_path,
                "-pubkey",
                "-noout",
                "-out", pubkey_path
            ]
            
            extract_result = run_openssl_command(extract_command)
            if not extract_result["success"]:
                return extract_result
            
            # Generate a random symmetric key and IV
            with tempfile.NamedTemporaryFile(delete=False) as temp_symkey:
                symkey_path = temp_symkey.name
            
            with tempfile.NamedTemporaryFile(delete=False) as temp_iv:
                iv_path = temp_iv.name
            
            # Generate 32-byte key and 12-byte IV (for GCM mode)
            symkey_command = ["openssl", "rand", "-out", symkey_path, "32"]
            iv_command = ["openssl", "rand", "-out", iv_path, "12"]
            
            symkey_result = run_openssl_command(symkey_command)
            if not symkey_result["success"]:
                return symkey_result
            
            iv_result = run_openssl_command(iv_command)
            if not iv_result["success"]:
                return iv_result
            
            # Encrypt the symmetric key with the recipient's public key
            with tempfile.NamedTemporaryFile(delete=False) as temp_enc_symkey:
                enc_symkey_path = temp_enc_symkey.name
            
            enc_symkey_command = [
                "openssl", "pkeyutl",
                "-encrypt",
                "-pubin",
                "-inkey", pubkey_path,
                "-in", symkey_path,
                "-out", enc_symkey_path
            ]
            
            enc_symkey_result = run_openssl_command(enc_symkey_command)
            if not enc_symkey_result["success"]:
                return enc_symkey_result
            
            # Encrypt the file with the symmetric key using authenticated encryption
            enc_file_command = [
                "openssl", "enc",
                f"-{cipher}",
                "-in", full_input_path,
                "-out", full_output_path,
                "-K", open(symkey_path, 'rb').read().hex(),
                "-iv", open(iv_path, 'rb').read().hex()
            ]
            
            enc_file_result = run_openssl_command(enc_file_command)
            if not enc_file_result["success"]:
                return enc_file_result
            
            # Read the encrypted symmetric key and IV
            with open(enc_symkey_path, 'rb') as f:
                enc_symkey = base64.b64encode(f.read()).decode('utf-8')
            with open(iv_path, 'rb') as f:
                iv = base64.b64encode(f.read()).decode('utf-8')
            
            return ResponseWrapper.success_response(
                f"Encrypted file {input_path} to {output_path}",
                {
                    "encrypted_file": os.path.relpath(full_output_path, self.working_dir),
                    "encrypted_key": enc_symkey,
                    "iv": iv,
                    "cipher": cipher
                }
            )
        finally:
            # Clean up temporary files
            for temp_file in [pubkey_path, symkey_path, iv_path, enc_symkey_path]:
                try:
                    if os.path.exists(temp_file):
                        os.unlink(temp_file)
                except Exception:
                    pass
    
    def decrypt_file(self, input_path: str, key_name: str, encrypted_key: str,
                     output_path: str, iv: str, cipher: str = "aes-256-gcm") -> Dict[str, Any]:
        """Decrypt a file using the private key and encrypted symmetric key.
        
        Args:
            input_path: Path to the encrypted file
            key_name: Name of the private key
            encrypted_key: Base64-encoded encrypted symmetric key
            output_path: Path where to save the decrypted file
            iv: Base64-encoded initialization vector
            cipher: FIPS-compliant cipher used for encryption
            
        Returns:
            Dictionary containing the operation result
        """
        input_path = input_path.strip()
        key_name = key_name.strip()
        output_path = output_path.strip()
        cipher = cipher.strip().lower()
        
        # Validate parameters
        if not all([input_path, key_name, encrypted_key, output_path, iv]):
            return ResponseWrapper.error_response(
                "All parameters (input_path, key_name, encrypted_key, output_path, iv) are required")
        
        # Validate cipher
        supported_ciphers = self.get_supported_ciphers()
        if not supported_ciphers["success"]:
            return supported_ciphers
        
        if cipher not in supported_ciphers["data"]["ciphers"]:
            return ResponseWrapper.error_response(
                f"Unsupported cipher: {cipher}. Please use a FIPS-compliant cipher.")
        
        # Set file paths
        full_input_path = os.path.join(self.files_dir, input_path)
        private_key_path = os.path.join(self.keys_dir, f"{key_name}.key")
        full_output_path = os.path.join(self.files_dir, output_path)
        
        # Check paths are safe
        if not is_safe_path(self.working_dir, full_input_path) or \
           not is_safe_path(self.working_dir, full_output_path):
            return ResponseWrapper.error_response("Path outside working directory not allowed")
        
        # Check if files exist and are readable
        try:
            if not os.path.exists(full_input_path):
                return ResponseWrapper.error_response(f"Input file {input_path} does not exist")
            if not os.access(full_input_path, os.R_OK):
                return ResponseWrapper.error_response(f"Input file {input_path} is not readable")
            if not os.path.exists(private_key_path):
                return ResponseWrapper.error_response(f"Private key {key_name}.key does not exist")
        except Exception as e:
            return ResponseWrapper.error_response(f"Error checking file access: {str(e)}")
        
        try:
            # Create temporary files for the encrypted and decrypted symmetric key
            with tempfile.NamedTemporaryFile(delete=False) as temp_enc_symkey:
                temp_enc_symkey.write(base64.b64decode(encrypted_key))
                enc_symkey_path = temp_enc_symkey.name
            
            with tempfile.NamedTemporaryFile(delete=False) as temp_symkey:
                symkey_path = temp_symkey.name
            
            # Decrypt the symmetric key with the private key
            dec_symkey_command = [
                "openssl", "pkeyutl",
                "-decrypt",
                "-inkey", private_key_path,
                "-in", enc_symkey_path,
                "-out", symkey_path
            ]
            
            dec_symkey_result = run_openssl_command(dec_symkey_command)
            if not dec