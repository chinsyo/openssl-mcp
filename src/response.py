from dataclasses import dataclass
from typing import Optional, Dict, Any

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
    def success_response(cls, output: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create a success response with output message and optional data.
        
        Args:
            output: A descriptive message about the successful operation
            data: Optional dictionary containing additional response data
            
        Returns:
            A dictionary containing the formatted success response
        """
        return cls(success=True, output=output, data=data).__dict__

    @classmethod
    def error_response(cls, error: str) -> Dict[str, Any]:
        """Create an error response with error message.
        
        Args:
            error: A descriptive error message
            
        Returns:
            A dictionary containing the formatted error response
        """
        return cls(success=False, error=error).__dict__