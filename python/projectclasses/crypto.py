from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import datetime

class Certificate:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.certificate = None

    def generate_keys(self):
        # Generate a RSA private/public key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def generate_certificate(self, subject_name, issuer_name):
        # Create a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "My Organization"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_name),
        ])
        
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(self.private_key, hashes.SHA256())
        )

    def serialize_private_key(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    def serialize_certificate(self):
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    def load_certificate(self, cert_pem):
        self.certificate = x509.load_pem_x509_certificate(cert_pem)

    def load_private_key(self, key_pem):
        self.private_key = serialization.load_pem_private_key(key_pem, password=None)
