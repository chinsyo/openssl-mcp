import unittest
from openssl_mcp.utils import *
import os

class TestUtils(unittest.TestCase):
    def test_ensure_directory_exists(self):
        # Test directory creation
        test_dir = "test_dir"
        ensure_directory_exists(test_dir)
        
        self.assertTrue(os.path.exists(test_dir))
        self.assertTrue(os.path.isdir(test_dir))
        
        # Clean up
        os.rmdir(test_dir)
    
    def test_is_valid_path(self):
        # Test valid paths
        self.assertTrue(is_valid_path("valid/path/file.txt"))
        self.assertTrue(is_valid_path("file.txt"))
        
        # Test invalid paths
        self.assertFalse(is_valid_path("../invalid/path"))
        self.assertFalse(is_valid_path("/root/absolute/path"))