import os
import subprocess
from typing import List, Dict, Any
from response import ResponseWrapper

def is_safe_path(base_path: str, path: str) -> bool:
    """Ensure path stays within working directory.
    
    Args:
        base_path: The base directory path that should contain the target path
        path: The target path to check
        
    Returns:
        True if the path is safe (within base_path), False otherwise
    """
    abs_base = os.path.abspath(base_path)
    abs_path = os.path.abspath(path)
    return abs_path.startswith(abs_base)

def run_openssl_command(command: List[str]) -> Dict[str, Any]:
    """Run OpenSSL command and return structured response.
    
    Args:
        command: List of command components to execute
        
    Returns:
        A dictionary containing the command execution result
    """
    try:
        # Get openssl path from which command
        openssl_path = subprocess.check_output(['which', 'openssl']).decode().strip()
        # Replace the first element (openssl) with the full path
        command[0] = openssl_path
        
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True
        )
        return ResponseWrapper.success_response(result.stdout.strip())
    except subprocess.CalledProcessError as e:
        return ResponseWrapper.error_response(e.stderr.strip())
    except Exception as e:
        return ResponseWrapper.error_response(str(e))


def validate_file_path(base_dir: str, *path_segments) -> Tuple[bool, str]:
    """
    50: # Security verification for file path within working directory
    53: Tuple[is_valid, normalized_path]
    """
    try:
        full_path = os.path.normpath(os.path.join(base_dir, *path_segments))
        if os.path.commonpath([base_dir, full_path]) != os.path.normpath(base_dir):
            return False, ""
        return True, full_path
    except Exception:
        return False, ""