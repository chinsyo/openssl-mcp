from enum import Enum, auto
from typing import List, Optional, Union
from pydantic import BaseModel, Field, constr

class KeyType(str, Enum):
    RSA = "rsa"
    DSA = "dsa"
    EC = "ec"

class KeySize(int, Enum):
    RSA_2048 = 2048
    RSA_3072 = 3072
    RSA_4096 = 4096
    DSA_2048 = 2048
    DSA_3072 = 3072
    EC_256 = 256

class CertificateStatus(str, Enum):
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"

class RevocationReason(int, Enum):
    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    REMOVE_FROM_CRL = 8
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10

class OpenSSLCommand(BaseModel):
    command: str
    args: List[str] = Field(default_factory=list)
    cwd: Optional[str] = None

class KeyPairConfig(BaseModel):
    key_name: str = Field(..., min_length=3, max_length=64, example="server_key")
    key_type: Literal['rsa', 'dsa', 'ec'] = 'rsa'
    key_size: int = Field(2048, gt=1024, le=4096, example=2048)

class CertificateConfig(BaseModel):
    key_name: str = Field(..., description="Associated key name", example="server_key")
    common_name: str = Field(..., max_length=64, example="example.com")
    days: int = Field(365, gt=0, example=365)
    cert_name: Optional[str] = Field(None, max_length=64, example="web_server_cert")
    is_ca: bool = False

class CRLConfig(BaseModel):
    ca_key: str = Field(..., example="ca_key")
    ca_cert: str = Field(..., example="ca_cert")
    serial_numbers: List[str] = Field(..., min_items=1, example=["001"])
    days: int = Field(30, gt=0, example=30)
    crl_name: Optional[str] = Field(None, example="2024_crl")

class OCSPConfig(BaseModel):
    ca_key: constr(strip_whitespace=True, min_length=1)
    ca_cert: constr(strip_whitespace=True, min_length=1)
    cert_name: constr(strip_whitespace=True, min_length=1)
    status: CertificateStatus = CertificateStatus.GOOD
    revocation_time: Optional[str] = None
    revocation_reason: Optional[RevocationReason] = None