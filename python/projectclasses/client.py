from projectclasses.tcp import TCP
from projectclasses.tls import TLS
import os
import struct
import time
import logging

class Client:
    def __init__(self, host, port):
        self.tcp = TCP(host, port)
        self.tls = None
        self.client_random = None
        self.logger = logging.getLogger('Client')

    def connect(self):
        """Establish connection and perform TLS handshake"""
        try:
            # Step 1: Establish TCP connection
            self.tcp.connect()
            self.logger.info("TCP connection established")

            # Step 2: Initialize TLS instance and perform handshake
            self.client_random = self._generate_client_random()
            self.tls = TLS(self.tcp, 5,supported_suites=[TLS.RSA_SUITE])  # or DHE_SUITE
            
            # Start TLS handshake
            print("Do we reach this point?")
            self.tls.send_client_hello(self.client_random)
            print("2")
            self.logger.info("TLS handshake initiated")

            # Receive and process server response
            content_type, version, server_hello = self.tls.receive_tls_record()
            if content_type != 22:  # Handshake type
                raise ValueError("Unexpected message type during handshake")

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
        self.tls.send_tls_record(23, (3, 3), data)  # 23 = Application Data
        self.logger.debug(f"Sent {len(data)} bytes")

    def receive(self) -> bytes:
        """Receive and decrypt application data"""
        if not self.tls:
            raise RuntimeError("TLS connection not established")
        content_type, version, data = self.tls.receive_tls_record()
        self.logger.debug(f"Received {len(data)} bytes")
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