import os
from typing import List, Dict, Any, Optional
from .openssl_models import (
    OpenSSLCommand, KeyPairConfig, CertificateConfig,
    CRLConfig, OCSPConfig, KeyType, KeySize
)
from .response import ResponseWrapper

class OpenSSLCommandBuilder:
    @staticmethod
    def build_key_pair_command(config: KeyPairConfig, working_dir: str) -> OpenSSLCommand:
        private_key_path = os.path.join(working_dir, "keys", f"{config.key_name}.key")
        public_key_path = os.path.join(working_dir, "keys", f"{config.key_name}.pub")
        
        if config.key_type == KeyType.RSA:
            return OpenSSLCommand(
                command="openssl",
                args=[
                    "genpkey",
                    "-algorithm", "RSA",
                    "-pkeyopt", f"rsa_keygen_bits:{config.key_size}",
                    "-out", private_key_path
                ]
            )
        elif config.key_type == KeyType.DSA:
            param_path = os.path.join(working_dir, "keys", f"{config.key_name}.param")
            return OpenSSLCommand(
                command="openssl",
                args=[
                    "dsaparam",
                    "-out", param_path,
                    str(config.key_size)
                ]
            )
        else:  # EC
            return OpenSSLCommand(
                command="openssl",
                args=[
                    "ecparam",
                    "-name", "prime256v1",
                    "-genkey",
                    "-out", private_key_path
                ]
            )
    
    @staticmethod
    def build_extract_public_key_command(private_key_path: str, public_key_path: str) -> OpenSSLCommand:
        return OpenSSLCommand(
            command="openssl",
            args=[
                "pkey",
                "-in", private_key_path,
                "-pubout",
                "-out", public_key_path
            ]
        )
    
    @staticmethod
    def build_certificate_command(config: CertificateConfig, working_dir: str, config_path: str) -> OpenSSLCommand:
        try:
            validate_config_path(config_path)
            return OpenSSLCommand(
                command='req',
                args=[
                    '-x509',
                    '-new',
                    '-key', os.path.join(working_dir, 'keys', f'{config.key_name}.key'),
                    '-out', os.path.join(working_dir, 'certificates', f'{config.cert_name or config.key_name}.crt'),
                    '-days', str(config.days),
                    '-config', config_path,
                    '-extensions', 'v3_ca' if config.is_ca else 'v3_req'
                ]
            )
        except (ValueError, FileNotFoundError) as e:
            raise OpenSSLCommandError(f"Certificate command construction failed: {str(e)}") from e
    
    @staticmethod
    def build_crl_command(config: CRLConfig, working_dir: str, revoke_path: str) -> OpenSSLCommand:
        ca_key_path = os.path.join(working_dir, "keys", f"{config.ca_key}.key")
        ca_cert_path = os.path.join(working_dir, "certificates", f"{config.ca_cert}.crt")
        crl_name = config.crl_name or config.ca_cert
        crl_path = os.path.join(working_dir, "crl", f"{crl_name}.crl")
        
        return OpenSSLCommand(
            command="openssl",
            args=[
                "ca",
                "-gencrl",
                "-keyfile", ca_key_path,
                "-cert", ca_cert_path,
                "-out", crl_path,
                "-crldays", str(config.days),
                "-revoke", revoke_path,
                "-md", "sha256"
            ]
        )
    
    @staticmethod
    def build_ocsp_command(config: OCSPConfig, working_dir: str) -> OpenSSLCommand:
        ca_key_path = os.path.join(working_dir, "keys", f"{config.ca_key}.key")
        ca_cert_path = os.path.join(working_dir, "certificates", f"{config.ca_cert}.crt")
        cert_path = os.path.join(working_dir, "certificates", f"{config.cert_name}.crt")
        
        args = [
            "ocsp",
            "-index", os.path.join(working_dir, "index.txt"),
            "-CA", ca_cert_path,
            "-rsigner", ca_cert_path,
            "-rkey", ca_key_path,
            "-cert", cert_path
        ]
        
        if config.status == "revoked":
            args.extend([
                "-revoked",
                "-rtime", config.revocation_time,
                "-reason", str(config.revocation_reason.value)
            ])
        
        return OpenSSLCommand(command="openssl", args=args)