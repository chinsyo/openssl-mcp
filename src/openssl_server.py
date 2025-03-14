from mcp.server.fastmcp import FastMCP
import os
from cert_manager import CertificateManager
from crypto import CryptoManager

from dataclasses import dataclass
from contextlib import asynccontextmanager
from typing import AsyncIterator

@dataclass
class AppContext:
    cert_manager: CertificateManager
    crypto_manager: CryptoManager

@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """管理应用生命周期，提供类型安全的上下文"""
    try:
        # 初始化工作目录和管理器
        os.makedirs(WORKING_DIR, exist_ok=True)
        cert_mgr = CertificateManager(WORKING_DIR)
        crypto_mgr = CryptoManager(WORKING_DIR)
        yield AppContext(cert_manager=cert_mgr, crypto_manager=crypto_mgr)
    finally:
        # 清理资源
        pass

# 初始化MCP服务器
mcp = FastMCP(
    name="OpenSSLServer",
    description="A server for certificate management and encryption with OpenSSL",
    version="0.1.0",
    lifespan=app_lifespan
)

# Define working directory for security
WORKING_DIR = os.path.expanduser("~/openssl_mcp_files")
os.makedirs(WORKING_DIR, exist_ok=True)

@mcp.tool()
def generate_key_pair(ctx: AppContext, key_name: str, key_type: str = "rsa", key_size: int = 2048) -> dict:
    """Generate a new key pair (private and public keys).
    
    Args:
        key_name: Name for the key pair
        key_type: Type of key to generate (rsa, dsa, or ec)
        key_size: Size of the key in bits
        
    Returns:
        Dictionary containing the operation result
    """
    return ctx.cert_manager.generate_key_pair(key_name, key_type, key_size)

@mcp.tool()
def create_certificate(ctx: AppContext, key_name: str, common_name: str, days: int = 365, cert_name: str = None) -> dict:
    """Create a self-signed certificate using an existing key pair.
    
    Args:
        key_name: Name of the key pair to use
        common_name: Common Name (CN) for the certificate
        days: Validity period in days
        cert_name: Optional name for the certificate (defaults to key_name)
        
    Returns:
        Dictionary containing the operation result
    """
    return ctx.cert_manager.create_certificate(key_name, common_name, days, cert_name)

@mcp.tool()
def verify_certificate(ctx: AppContext, cert_name: str) -> dict:
    """Verify a certificate and display its information.
    
    Args:
        cert_name: Name of the certificate to verify
        
    Returns:
        Dictionary containing the operation result
    """
    return ctx.cert_manager.verify_certificate(cert_name)

@mcp.tool()
def verify_certificate_chain(ctx: AppContext, cert_name: str, ca_cert_name: str) -> dict:
    """Verify a certificate against a CA certificate.
    
    Args:
        cert_name: Name of the certificate to verify
        ca_cert_name: Name of the CA certificate
        
    Returns:
        Dictionary containing the operation result
    """
    return ctx.cert_manager.verify_certificate_chain(cert_name, ca_cert_name)

@mcp.tool()
def export_pkcs12(ctx: AppContext, key_name: str, cert_name: str = None, password: str = None) -> dict:
    """Export certificate and private key to PKCS12 format.
    
    Args:
        key_name: Name of the key pair
        cert_name: Optional name for the certificate (defaults to key_name)
        password: Optional password for the PKCS12 file
        
    Returns:
        Dictionary containing the operation result
    """
    return ctx.crypto_manager.export_pkcs12(key_name, cert_name, password)

@mcp.tool()
def encrypt_file(ctx: AppContext, input_path: str, recipient_cert: str, output_path: str) -> dict:
    """Encrypt a file using a recipient's certificate (public key).
    
    Args:
        input_path: Path to the file to encrypt
        recipient_cert: Name of the recipient's certificate
        output_path: Path where to save the encrypted file
        
    Returns:
        Dictionary containing the operation result
    """
    return ctx.crypto_manager.encrypt_file(input_path, recipient_cert, output_path)

@mcp.tool()
def decrypt_file(ctx: AppContext, input_path: str, key_name: str, encrypted_key: str, output_path: str) -> dict:
    """Decrypt a file using the private key and encrypted symmetric key.
    
    Args:
        input_path: Path to the encrypted file
        key_name: Name of the private key
        encrypted_key: Base64-encoded encrypted symmetric key
        output_path: Path where to save the decrypted file
        
    Returns:
        Dictionary containing the operation result
    """
    return ctx.crypto_manager.decrypt_file(input_path, key_name, encrypted_key, output_path)