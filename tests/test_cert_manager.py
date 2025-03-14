import unittest
from src.cert_manager import *
import tempfile
import os

class TestCertManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cert_path = os.path.join(self.temp_dir, "test.crt")
        self.key_path = os.path.join(self.temp_dir, "test.key")
    
    def tearDown(self):
        # Clean up temporary files
        for file in [self.cert_path, self.key_path]:
            if os.path.exists(file):
                os.remove(file)
        os.rmdir(self.temp_dir)
    
    def test_certificate_generation(self):
        # Test certificate generation
        generate_self_signed_cert(self.cert_path, self.key_path)
        
        # Verify files exist
        self.assertTrue(os.path.exists(self.cert_path))
        self.assertTrue(os.path.exists(self.key_path))
        
        # Verify file permissions
        self.assertEqual(os.stat(self.key_path).st_mode & 0o777, 0o600)
    
    def test_invalid_key_type(self):
        manager = CertificateManager(self.temp_dir)
        result = manager.generate_key_pair("invalid_key", key_type="invalid")
        self.assertEqual(result['status'], 'error')
        self.assertIn('Invalid key type', result['error'])

    def test_certificate_chain_validation(self):
        # 生成根CA证书
        self.mgr.generate_key_pair('root_ca')
        root_ca = self.mgr.create_certificate('root_ca', 'Root CA', is_ca=True)
        
        # 生成中间证书
        self.mgr.generate_key_pair('intermediate')
        intermediate = self.mgr.create_certificate('intermediate', 'Intermediate CA', 
                                                  parent_ca='root_ca', is_ca=True)
        
        # 验证证书链
        chain_status = self.mgr.verify_certificate_chain(intermediate['cert_path'],
                                                        root_ca['cert_path'])
        self.assertTrue(chain_status['valid'])
        
        # 测试证书链深度限制
        self.mgr.generate_key_pair('end_entity')
        end_entity = self.mgr.create_certificate('end_entity', 'End Entity',
                                                parent_ca='intermediate',
                                                max_path_length=0)
        
        # 验证三级证书链应失败
        with self.assertRaises(OpenSSLValidationError):
            self.mgr.verify_certificate_chain(end_entity['cert_path'],
                                            root_ca['cert_path'],
                                            max_depth=2)
        
        # 测试无效序列号格式
        invalid_crl = self.mgr.create_crl(ca_key='root_ca', ca_cert='root_ca',
                                        serial_numbers=['INVALID-123'])
        self.assertFalse(invalid_crl['valid'])

    def test_invalid_serial_number(self):
        # 测试无效序列号格式
        self.mgr.create_certificate('ca', 'Test CA', is_ca=True)
        with self.assertRaises(ValueError):
            self.mgr.create_crl(ca_key='ca', ca_cert='ca',
                               serial_numbers=['INVALID123'], days=30)

    def test_crl_integration(self):
        # 创建CA
        self.mgr.create_certificate('ca', 'Test CA', is_ca=True)
        # 生成CRL
        crl = self.mgr.create_crl('ca', 'ca', ['001'])
        self.assertTrue(os.path.exists(crl['crl_path']))
        # 验证CRL包含撤销序列号
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