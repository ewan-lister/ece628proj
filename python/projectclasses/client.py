from projectclasses.tcp import TCP
from projectclasses.tls import TLS
from projectclasses.crypto import Certificate
import os
import struct
import time
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class Client:

    RSA_SUITE = "TLS_RSA_WITH_AES_256_CBC_SHA256"
    DHE_SUITE = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"

    CIPHER_SUITE_MAP = {
        RSA_SUITE: 0x003D,
        DHE_SUITE: 0x006B
    }

    def __init__(self, host, port, supported_suite = None):  
        self.tcp = TCP(host, port)
        self.tls = None
        self.client_random = None
        self.server_random = None
        self.connection_id = id
        self.supported_suite = supported_suite
        self.logger = logging.getLogger('Client')
        
        # Only log connection once
        self.logger.info(f"Connecting to {host}:{port}")

        # Initialize client certificate
        self.certificate = Certificate()
        self.certificate.generate_keys()
        self.certificate.generate_certificate(
            subject_name=f"TLS Client {host}:{port}",
            issuer_name="TLS Client CA"
        )

    def connect(self):
        """Establish connection and perform TLS handshake"""
        try:
            # Step 1: Establish TCP connection
            self.tcp.connect()

            # Step 2: Initialize TLS instance and perform handshake
            self.client_random = self._generate_client_random()
            self.tls = TLS(self.tcp,supported_suites=self.supported_suite)  # or DHE_SUITE
            
            # Start TLS handshake
            self.tls.send_client_hello(self.client_random)
            self.logger.info("TLS handshake initiated")

            # Receive and process server response
            server_random, chosen_cipher = self.tls.receive_server_hello()

            if chosen_cipher == self.CIPHER_SUITE_MAP[self.RSA_SUITE]:
                shared_secret = self.rsa_handshake(self.client_random, server_random)
            else:
                shared_secret = self.dhe_handshake(self.client_random, server_random)

            self.tls.derive_keys(is_client=True)
            self.tls.send_finished()
            self.tls.receive_finished()
            # Complete remaining handshake steps...
            self.logger.info("TLS handshake completed")

        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            self.close()
            raise

    def send(self, data: bytes):
        """Send encrypted application data"""
        if not self.tls:
            raise RuntimeError("TLS connection not established")
        self.tls.send_application_data(data)
        self.logger.debug(f"Sent encrypted data: {len(data)} bytes")

    def receive(self) -> bytes:
        """Receive and decrypt application data"""
        if not self.tls:
            raise RuntimeError("TLS connection not established")
        data = self.tls.receive_application_data()
        self.logger.debug(f"Received decrypted data: {len(data)} bytes")
        return data

    def close(self):
        """Close connection and cleanup"""
        if self.tcp:
            self.tcp.close()
            self.logger.info("Connection closed")

    def _generate_client_random(self) -> bytes:
        """Generate the client random (32 bytes: 4 byte timestamp + 28 random bytes)"""
        timestamp = struct.pack("!I", int(time.time()))
        random_bytes = os.urandom(28)
        return timestamp + random_bytes
    
    def rsa_handshake(self, client_random, server_random):
        """Perform RSA handshake"""
        # Placeholder for RSA handshake logic
        server_certificate = self.tls.receive_server_certificate()
        valid, server_signing_key = self.tls.verify_certificate(server_certificate)
        if not valid:
            raise Exception("Invalid server certificate")
        # receive server certificate request
        self.tls.receive_certificate_request()
        #receive server hello done
        self.tls.receive_server_hello_done()

        # send client certificate
        self.tls.send_client_certificate(self.certificate)
        # send client key exchange
        premaster_secret = self.tls.send_rsa_client_key_exchange(server_signing_key, self.certificate.private_key)

        # send certificate verify
        self.tls.send_certificate_verify(self.certificate.private_key)

        # send change cipher spec
        self.tls.send_change_cipher_spec()

    def dhe_handshake(self, client_random, server_random):
        """Perform DHE handshake"""
        # Placeholder for DHE handshake logic
        server_certificate = self.tls.receive_server_certificate()
        valid, server_signing_key = self.tls.verify_certificate(server_certificate)
        if not valid:
            raise Exception("Invalid server certificate")
        
        # receive server key exchange

        parameters, server_dhe_public_key = self.tls.receive_server_key_exchange_dhe(server_signing_key)
        # receive server certificate request
        self.tls.receive_certificate_request()
        #receive server hello done
        self.tls.receive_server_hello_done()

        # send client certificate
        self.tls.send_client_certificate(self.certificate)
        # send client key exchange
        premaster_secret = self.tls.send_client_key_exchange_dhe(parameters)
        # print("5")

        # send certificate verify
        self.tls.send_certificate_verify(self.certificate.private_key)

        # send change cipher spec
        self.tls.send_change_cipher_spec()



