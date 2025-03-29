import struct
import logging
from projectclasses.tcp import TCP
from typing import Optional, Dict

class TLS:
    # Static cipher suite definitions
    RSA_SUITE = "TLS_RSA_WITH_AES_256_GCM_SHA256"
    DHE_SUITE = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
    
    CIPHER_SUITE_MAP = {
        RSA_SUITE: 0x003D,
        DHE_SUITE: 0x006B
    }

    def __init__(self, tcp_connection, connection_id: Optional[int] = None, 
                 supported_suites: Optional[list] = None):
        self.tcp = tcp_connection
        self.connection_id = connection_id
        self.logger = logging.getLogger(__name__)
        self.chosen_cipher = None
        self.client_random = None
        self.server_random = None
        # Default to supporting all suites if none specified
        self.supported_suites = supported_suites or self.CIPHER_SUITE_MAP

    def send_handshake_message(self, handshake_type, message):
        # Handshake header: [Handshake Type (1 byte)] + [Length (3 bytes)]
        header = struct.pack("!B3s", handshake_type, len(message).to_bytes(3, 'big'))
        print("4")
        version = (3, 3)  # TLS 1.2)
        self.send_tls_record(22, version, header + message)  # Content Type 22 = Handshake
        
    def send_tls_record(self, content_type: int, version: tuple, payload: bytes):
        """Send TLS record
        Args:
            content_type (int): Record type (e.g., 22 for Handshake)
            version (tuple): Protocol version as (major, minor)
            payload (bytes): Record payload
        """
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
            
        # Pack header: content_type (1 byte), version (2 bytes), length (2 bytes)
        record = struct.pack('!BBBH', 
            content_type,    # 1 byte
            version[0],      # 1 byte (major)
            version[1],      # 1 byte (minor)
            len(payload)     # 2 bytes (length)
        ) + payload

        self.tcp.send(record, self.connection_id)

    def receive_tls_record(self):
        """Receive TLS record using connection ID if server
        Returns:
            tuple: (content_type, version, payload)
            - content_type (int): Record type (e.g., 22 for Handshake)
            - version (tuple): Protocol version as (major, minor)
            - payload (bytes): Record payload
        """
        # Read TLS header (5 bytes)
        header = self.tcp.receive(5, self.connection_id)
        if len(header) < 5:
            raise ConnectionError("Incomplete TLS header received")

        # Unpack header components
        content_type = header[0]
        version = (header[1], header[2])
        length = int.from_bytes(header[3:5], byteorder='big')

        # Receive payload
        payload = self.tcp.receive(length, self.connection_id)
        if len(payload) < length:
            raise ConnectionError(f"Incomplete payload received: {len(payload)} < {length}")

        self.logger.info(f"Received TLS record (type {content_type}, length {length})")
        return content_type, version, payload
    
    # handshake methods
    # ----------------------------------------------------------------------------
    def negotiate_cipher_suites(self, client_suites):
        # Negotiates a cipher suite with the client
        supported_suites = ["TLS_RSA_WITH_AES_256_CBC_SHA_256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"]
        for suite in client_suites:
            if suite in supported_suites:
                self.chosen_cipher = suite
                return suite
        raise ValueError("No common cipher suite found")
    
    def send_client_hello(self, client_random):
        """Send ClientHello message with specified cipher suites"""
        # Protocol Version (TLS 1.2)
        version = struct.pack("!BB", 3, 3)
        
        # Session ID (empty)
        session_id = struct.pack("!B", 0)  # Just length byte of 0
        
        # Cipher Suites
        supported_suite_bytes = b""
        for suite in self.supported_suites:
            supported_suite_bytes += struct.pack("!H", self.CIPHER_SUITE_MAP[suite])
        cipher_suites = struct.pack("!H", len(supported_suite_bytes)) + supported_suite_bytes
        
        # Compression Methods (null only)
        compression = struct.pack("!BB", 1, 0)  # Length 1, null compression
        
        client_hello = (
            version +
            client_random +
            session_id +
            cipher_suites +
            compression
        )
        print("3")
        self.send_handshake_message(1, client_hello)

    #def receive_client_hello(self):

    def send_server_hello(self):
        # Send ServerHello message
        server_hello = b"ServerHello"
        self.send_handshake_message(2, server_hello)

    #def receive_server_hello(self):

    def send_server_certificate(self):
        # Send Certificate message
        certificate = b"Certificate"
        self.send_handshake_message(11, certificate)

    def receive_server_certificate(self):
        # Receive Certificate message
        _, _, certificate = self.receive_tls_record()
        return certificate
    
    def send_server_key_exchange(self):
        # Send ServerKeyExchange message
        key_exchange = b"ServerKeyExchange"
        self.send_handshake_message(12, key_exchange)
    
    def receive_server_key_exchange(self):
        # Receive ServerKeyExchange message
        _, _, key_exchange = self.receive_tls_record()
        return key_exchange
    
    def certificate_request(self):
        # Send CertificateRequest message
        request = b"CertificateRequest"
        self.send_handshake_message(13, request)
    
    def receive_certificate_request(self):
        # Receive CertificateRequest message
        _, _, request = self.receive_tls_record()
        return request
    
    def send_server_hello_done(self):
        # Send ServerHelloDone message
        server_hello_done = b"ServerHelloDone"
        self.send_handshake_message(14, server_hello_done)

    def client_key_exchange(self):
        # Send ClientKeyExchange message
        key_exchange = b"ClientKeyExchange"
        self.send_handshake_message(16, key_exchange)

    #def receive_client_key_exchange(self):
