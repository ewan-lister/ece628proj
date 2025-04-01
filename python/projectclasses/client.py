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

        # Initialize timing metrics
        self.last_cert_time = 0
        self.last_server_msgs_time = 0
        self.last_cert_send_time = 0
        self.last_key_exchange_time = 0
        self.last_verify_time = 0
        self.last_cipher_spec_time = 0
        self.last_dh_params_time = 0
        self.last_total_time = 0

    def connect(self):
        """Establish connection and perform TLS handshake"""
        try:
            self.tcp.connect()
            self.client_random = self._generate_client_random()
            self.tls = TLS(self.tcp, supported_suites=self.supported_suite)
            
            # Start TLS handshake
            self.tls.send_client_hello(self.client_random)
            self.logger.info("TLS handshake initiated")

            # Process server response
            server_random, chosen_cipher = self.tls.receive_server_hello()

            # Perform appropriate handshake
            if chosen_cipher == self.CIPHER_SUITE_MAP[self.RSA_SUITE]:
                shared_secret = self.rsa_handshake(self.client_random, server_random)
            else:
                shared_secret = self.dhe_handshake(self.client_random, server_random)

            # Complete handshake
            self.tls.derive_keys(is_client=True)
            self.tls.send_finished()
            self.tls.receive_finished()
            self.logger.info("TLS handshake completed")

            # Verify encryption is working with smaller test data
            test_data = b"test"
            try:
                self.send(test_data)
                response = self.receive()
                if response != test_data:
                    raise ValueError("Encryption verification failed")
                self.logger.debug("Encryption verified successfully")
            except Exception as e:
                self.logger.error(f"Encryption verification failed: {e}")
                raise ValueError("Encryption verification failed")

        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            self.close()
            raise

    def send(self, data):
        """Send encrypted application data"""
        if not self.tls:
            raise RuntimeError("TLS connection not established")
        
        # Convert string to bytes if necessary
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif not isinstance(data, bytes):
            raise TypeError("Data must be bytes or str")
            
        self.tls.send_application_data(data)
        self.logger.debug(f"Sent encrypted data: {len(data)} bytes")

    def receive(self) -> bytes:
        """Receive and decrypt application data"""
        if not self.tls:
            raise RuntimeError("TLS connection not established")
        data = self.tls.receive_application_data()
        self.logger.debug(f"Received decrypted data: {len(data)} bytes")
        return data  # Return raw bytes, let caller handle decoding

    def close(self):
        """Close connection gracefully"""
        try:
            if self.tls:
                # Send close_notify alert if TLS is established
                self.tls.send_alert(level=1, description=0)  # close_notify alert
            if self.tcp:
                self.tcp.close()
                self.logger.info("Connection closed cleanly")
        except Exception as e:
            self.logger.debug(f"Error during close: {e}")
        finally:
            self.tcp = None
            self.tls = None

    def _generate_client_random(self) -> bytes:
        """Generate the client random (32 bytes: 4 byte timestamp + 28 random bytes)"""
        timestamp = struct.pack("!I", int(time.time()))
        random_bytes = os.urandom(28)
        return timestamp + random_bytes
    
    def rsa_handshake(self, client_random, server_random):
        """Perform RSA handshake with detailed timing"""
        self.logger.info("\nStarting RSA Handshake:")
        self.logger.info("-" * 40)
        
        # Server Certificate phase
        start = time.time()
        server_certificate = self.tls.receive_server_certificate()
        valid, server_signing_key = self.tls.verify_certificate(server_certificate)
        if not valid:
            raise Exception("Invalid server certificate")
        cert_time = time.time() - start
        self.logger.info(f"Certificate processing: {cert_time:.6f}s")

        # Server messages phase
        start = time.time()
        self.tls.receive_certificate_request()
        self.tls.receive_server_hello_done()
        server_msgs_time = time.time() - start
        self.logger.info(f"Server messages: {server_msgs_time:.6f}s")

        # Client Certificate phase
        start = time.time()
        self.tls.send_client_certificate(self.certificate)
        cert_send_time = time.time() - start
        self.logger.info(f"Client certificate send: {cert_send_time:.6f}s")

        # Key Exchange phase
        start = time.time()
        premaster_secret = self.tls.send_rsa_client_key_exchange(
            server_signing_key, 
            self.certificate.private_key
        )
        key_exchange_time = time.time() - start
        self.logger.info(f"RSA key exchange: {key_exchange_time:.6f}s")

        # Verification phase
        start = time.time()
        self.tls.send_certificate_verify(self.certificate.private_key)
        verify_time = time.time() - start
        self.logger.info(f"Certificate verification: {verify_time:.6f}s")

        # Change Cipher Spec
        start = time.time()
        self.tls.send_change_cipher_spec()
        cipher_spec_time = time.time() - start
        self.logger.info(f"Change cipher spec: {cipher_spec_time:.6f}s")

        total_time = cert_time + server_msgs_time + cert_send_time + key_exchange_time + verify_time + cipher_spec_time
        self.logger.info("-" * 40)
        self.logger.info(f"Total RSA handshake time: {total_time:.6f}s\n")

        # Store timing metrics before returning
        self.last_cert_time = cert_time
        self.last_server_msgs_time = server_msgs_time
        self.last_cert_send_time = cert_send_time
        self.last_key_exchange_time = key_exchange_time
        self.last_verify_time = verify_time
        self.last_cipher_spec_time = cipher_spec_time
        self.last_total_time = total_time
        self.last_dh_params_time = 0  # Not used in RSA

        return premaster_secret

    def dhe_handshake(self, client_random, server_random):
        """Perform DHE handshake with detailed timing"""
        self.logger.info("\nStarting DHE Handshake:")
        self.logger.info("-" * 40)
        
        # Server Certificate phase
        start = time.time()
        server_certificate = self.tls.receive_server_certificate()
        valid, server_signing_key = self.tls.verify_certificate(server_certificate)
        if not valid:
            raise Exception("Invalid server certificate")
        cert_time = time.time() - start
        self.logger.info(f"Certificate processing: {cert_time:.6f}s")

        # DH Parameter Exchange phase
        start = time.time()
        parameters, server_dhe_public_key = self.tls.receive_server_key_exchange_dhe(server_signing_key)
        dh_params_time = time.time() - start
        self.logger.info(f"DH parameter exchange: {dh_params_time:.6f}s")

        # Server messages phase
        start = time.time()
        self.tls.receive_certificate_request()
        self.tls.receive_server_hello_done()
        server_msgs_time = time.time() - start
        self.logger.info(f"Server messages: {server_msgs_time:.6f}s")

        # Client Certificate phase
        start = time.time()
        self.tls.send_client_certificate(self.certificate)
        cert_send_time = time.time() - start
        self.logger.info(f"Client certificate send: {cert_send_time:.6f}s")

        # DH Key Exchange phase
        start = time.time()
        premaster_secret = self.tls.send_client_key_exchange_dhe(parameters)
        key_exchange_time = time.time() - start
        self.logger.info(f"DHE key exchange: {key_exchange_time:.6f}s")

        # Verification phase
        start = time.time()
        self.tls.send_certificate_verify(self.certificate.private_key)
        verify_time = time.time() - start
        self.logger.info(f"Certificate verification: {verify_time:.6f}s")

        # Change Cipher Spec and Finished messages
        start = time.time()
        self.tls.send_change_cipher_spec()
        cipher_spec_time = time.time() - start
        self.logger.info(f"Change cipher spec: {cipher_spec_time:.6f}s")

        # Store timing metrics
        total_time = cert_time + dh_params_time + server_msgs_time + cert_send_time + key_exchange_time + verify_time + cipher_spec_time
        self.logger.info("-" * 40)
        self.logger.info(f"Total DHE handshake time: {total_time:.6f}s\n")

        # Store timing metrics
        self.last_cert_time = cert_time
        self.last_server_msgs_time = server_msgs_time
        self.last_cert_send_time = cert_send_time
        self.last_key_exchange_time = key_exchange_time
        self.last_verify_time = verify_time
        self.last_cipher_spec_time = cipher_spec_time
        self.last_total_time = total_time
        self.last_dh_params_time = dh_params_time

        # NOTE: Let the connect() method handle the following:
        # - derive_keys()
        # - send_finished()
        # - receive_finished()
        
        return premaster_secret

    def get_timing_metrics(self):
        """Return dictionary of timing metrics from last handshake"""
        return {
            'cert_processing': self.last_cert_time,
            'server_messages': self.last_server_msgs_time,
            'cert_send': self.last_cert_send_time,
            'key_exchange': self.last_key_exchange_time,
            'cert_verify': self.last_verify_time,
            'cipher_spec': self.last_cipher_spec_time,
            'dh_params': self.last_dh_params_time,
            'total_time': self.last_total_time
        }

    def reset_timing_metrics(self):
        """Reset all timing metrics to zero"""
        self.last_cert_time = 0
        self.last_server_msgs_time = 0
        self.last_cert_send_time = 0
        self.last_key_exchange_time = 0
        self.last_verify_time = 0
        self.last_cipher_spec_time = 0
        self.last_dh_params_time = 0
        self.last_total_time = 0



