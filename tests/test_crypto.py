import unittest
from openssl_mcp.crypto import *

class TestCrypto(unittest.TestCase):
    def test_encryption_decryption(self):
        # Test data
        original_data = b"Test message"
        key = generate_key()
        
        # Test encryption
        encrypted = encrypt(key, original_data)
        self.assertNotEqual(encrypted, original_data)
        
        # Test decryption
        decrypted = decrypt(key, encrypted)
        self.assertEqual(decrypted, original_data)
        
    def test_key_generation(self):
        key1 = generate_key()
        key2 = generate_key()
        
        # Test that keys are unique
        self.assertNotEqual(key1, key2)
        
        # Test key length
        self.assertEqual(len(key1), 32)  # 256 bits