"""
Signature Verifier - Handle firmware signature verification
"""

import hashlib
import os
from utils.logger import get_logger

class SignatureVerifier:
    """Handles firmware signature verification"""

    def __init__(self):
        self.logger = get_logger()
        self.public_key = None
        self.verification_method = 'MD5'  # MD5, SHA256, RSA

    def set_verification_method(self, method):
        """Set verification method"""
        valid_methods = ['MD5', 'SHA256', 'RSA', 'NONE']
        if method in valid_methods:
            self.verification_method = method
            self.logger.info(f"Verification method set to: {method}")
            return True
        return False

    def load_public_key(self, key_path):
        """Load RSA public key for verification"""
        try:
            with open(key_path, 'rb') as f:
                self.public_key = f.read()
            self.logger.info("Public key loaded successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error loading public key: {e}")
            return False

    def calculate_checksum(self, data, method='MD5'):
        """Calculate checksum of data"""
        if method == 'MD5':
            return hashlib.md5(data).hexdigest()
        elif method == 'SHA256':
            return hashlib.sha256(data).hexdigest()
        else:
            return None

    def verify_firmware(self, firmware_data, expected_checksum=None):
        """Verify firmware integrity"""
        if self.verification_method == 'NONE':
            self.logger.info("Signature verification disabled")
            return True

        try:
            if self.verification_method in ['MD5', 'SHA256']:
                calculated = self.calculate_checksum(firmware_data, self.verification_method)
                self.logger.info(f"{self.verification_method} checksum: {calculated}")

                if expected_checksum:
                    if calculated.lower() == expected_checksum.lower():
                        self.logger.info("Checksum verification passed")
                        return True
                    else:
                        self.logger.error("Checksum verification failed")
                        return False
                else:
                    # No expected checksum, just log calculated
                    return True

            elif self.verification_method == 'RSA':
                if not self.public_key:
                    self.logger.warning("No public key loaded for RSA verification")
                    return False

                # RSA verification would go here
                # This is a placeholder for future implementation
                self.logger.info("RSA verification not yet fully implemented")
                return True

        except Exception as e:
            self.logger.error(f"Verification error: {e}")
            return False

        return True

    def verify_signature_file(self, firmware_path, signature_path):
        """Verify firmware using separate signature file"""
        try:
            # Load firmware
            with open(firmware_path, 'rb') as f:
                firmware_data = f.read()

            # Load signature
            with open(signature_path, 'r') as f:
                signature = f.read().strip()

            # Verify
            return self.verify_firmware(firmware_data, signature)

        except Exception as e:
            self.logger.error(f"Error verifying signature file: {e}")
            return False

    def generate_signature_file(self, firmware_path, output_path=None):
        """Generate signature file for firmware"""
        try:
            with open(firmware_path, 'rb') as f:
                firmware_data = f.read()

            checksum = self.calculate_checksum(firmware_data, self.verification_method)

            if not output_path:
                output_path = firmware_path + f'.{self.verification_method.lower()}'

            with open(output_path, 'w') as f:
                f.write(checksum)

            self.logger.info(f"Signature file created: {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"Error generating signature file: {e}")
            return False
