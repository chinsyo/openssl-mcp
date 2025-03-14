from dataclasses import dataclass
from typing import Optional, Dict, Any, Union

@dataclass
class SuccessResponse:
    output: str
    success: bool = True
    data: Optional[Dict[str, Any]] = None

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        setattr(self, key, value)

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key)

@dataclass
class ErrorResponse:
    error: str
    success: bool = False

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        setattr(self, key, value)

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key)

# Type alias for unified response type
ResponseType = Union[SuccessResponse, ErrorResponse]

@dataclass
class ResponseWrapper:
    """Unified response wrapper for all API endpoints.
    
    This class provides a standardized way to format responses across the application,
    ensuring consistency in the API responses.
    
    Attributes:
        success (bool): Indicates if the operation was successful
        output (Optional[str]): Output message for successful operations
        error (Optional[str]): Error message for failed operations
        data (Optional[dict]): Additional data associated with the response
    """
    success: bool
    output: Optional[str] = None
    error: Optional[str] = None
    data: Optional[Dict[str, Any]] = None

    @classmethod
    def success_response(cls, output: str, data: Optional[Dict[str, Any]] = None) -> 'SuccessResponse':
        return SuccessResponse(output=output, data=data)

    @classmethod
    def error_response(cls, error: str) -> 'ErrorResponse':
        return ErrorResponse(error=error)