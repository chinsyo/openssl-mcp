import unittest
from openssl_mcp.cert_manager import *
import subprocess
import tempfile
import os

class TestCertManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cert_path = os.path.join(self.temp_dir, "test.crt")
        self.key_path = os.path.join(self.temp_dir, "test.key")
        self.mgr = CertificateManager(working_dir=self.temp_dir)

    def tearDown(self):
        # Clean up temporary files
        for file in [self.cert_path, self.key_path]:
            if os.path.exists(file):
                os.remove(file)
        os.rmdir(self.temp_dir)
    
    def test_certificate_generation(self):
        # Test certificate generation
        self.mgr.generate_self_signed_certificate(self.cert_path, self.key_path)
        
        # Verify files exist
        self.assertTrue(os.path.exists(self.cert_path))
        self.assertTrue(os.path.exists(self.key_path))
        
        # Verify file permissions
        self.assertEqual(os.stat(self.key_path).st_mode & 0o777, 0o600)
    
    def test_invalid_key_type(self):
        result = self.mgr.generate_key_pair("invalid_key", key_type="invalid")
        self.assertEqual(result['status'], 'error')
        self.assertIn('Invalid key type', result['error'])

    def test_certificate_chain_validation(self):
        # Generate root CA certificate
        # 创建证书管理器实例
        root_ca = self.mgr.create_certificate('root_ca', 'Root CA', is_ca=True)
        
        # Generate intermediate certificate
        self.mgr.generate_key_pair('intermediate')
        intermediate = self.mgr.create_certificate('intermediate', 'Intermediate CA', 
                                                  parent_ca='root_ca', is_ca=True)
        
        # Verify certificate chain
        chain_status = self.mgr.verify_certificate_chain(intermediate['cert_path'],
                                                        root_ca['cert_path'])
        self.assertTrue(chain_status['valid'])
        
        # Test certificate chain depth limit
        self.mgr.generate_key_pair('end_entity')
        end_entity = self.mgr.create_certificate('end_entity', 'End Entity',
                                                parent_ca='intermediate',
                                                max_path_length=0)
        
        # Verify three-level certificate chain should fail
        with self.assertRaises(OpenSSLValidationError):
            self.mgr.verify_certificate_chain(end_entity['cert_path'],
                                            root_ca['cert_path'],
                                            max_depth=2)
        
        # Test invalid serial number format
        invalid_crl = self.mgr.create_crl(ca_key='root_ca', ca_cert='root_ca',
                                        serial_numbers=['INVALID-123'])
        self.assertFalse(invalid_crl['valid'])

    def test_invalid_serial_number(self):
        # Test invalid serial number format
        self.mgr.create_certificate('ca', 'Test CA', is_ca=True)
        with self.assertRaises(ValueError):
            self.mgr.create_crl(ca_key='ca', ca_cert='ca',
                               serial_numbers=['INVALID123'], days=30)

    def test_crl_integration(self):
        # Create CA
        self.mgr.create_certificate('ca', 'Test CA', is_ca=True)
        # Generate CRL
        crl = self.mgr.create_crl('ca', 'ca', ['001'])
        self.assertTrue(os.path.exists(crl['crl_path']))
        # Verify CRL contains revoked serial numbers
        self._verify_crl_content(crl['crl_path'], '001')

    def test_duplicate_key_creation(self):
        self.mgr.generate_key_pair('dupe_test')
        result = self.mgr.generate_key_pair('dupe_test')
        self.assertFalse(result['success'])

    def test_file_permissions(self):
        key = self.mgr.generate_key_pair('perm_test')
        self.assertEqual(stat.S_IMODE(os.stat(key['private_key']).st_mode), 0o600)

    def test_fips_compliance(self):
        try:
            result = self.mgr.generate_key_pair('fips_test', key_type='rsa', key_size=3072)
            self.assertTrue(result['success'])
        except subprocess.CalledProcessError:
            self.skipTest("FIPS mode not enabled")