import unittest
from openssl_mcp.response import *

class TestResponse(unittest.TestCase):
    def test_success_response(self):
        # Test success response creation
        data = {"key": "value"}
        response = create_success_response(data)
        
        self.assertEqual(response["status"], "success")
        self.assertEqual(response["data"], data)
        self.assertNotIn("error", response)
    
    def test_error_response(self):
        # Test error response creation
        error_msg = "Test error message"
        response = create_error_response(error_msg)
        
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["error"], error_msg)
        self.assertNotIn("data", response)