import struct
import logging
from projectclasses.tcp import TCP

class TLS:
    CIPHER_SUITES = {
        "TLS_RSA_WITH_AES_256_GCM_SHA256": 0x003D,
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": 0x006B
    }

    def __init__(self, tcp_connection):
        self.tcp = tcp_connection
        self.logger = logging.getLogger(__name__)

    def send_handshake_message(self, handshake_type, message):
        # Handshake header: [Handshake Type (1 byte)] + [Length (3 bytes)]
        header = struct.pack("!B3s", handshake_type, len(message).to_bytes(3, 'big'))
        self.send_tls_record(22, (3, 3), header + message)  # Content Type 22 = Handshake
        
    def send_tls_record(self, content_type: int, version: tuple, payload: bytes):
        if isinstance(payload, str):  # Ensure payload is bytes
            payload = payload.encode('utf-8')
        header = struct.pack("!BHH", content_type, (version[0] << 8) | version[1], len(payload))
        self.tcp.send(header + payload)

    def receive_tls_record(self):
        # Read TLS header (5 bytes)
        header = self.tcp.receive(5)
        if len(header) < 5:
            raise ConnectionError("Incomplete TLS header received")

        content_type = header[0]
        version = (header[1], header[2])
        length = struct.unpack("!H", header[3:5])[0]

        # Read full payload
        payload = self.tcp.receive(length)
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
    
    def send_client_hello(self):
        # Send ClientHello message
        client_hello = b"ClientHello"
        self.send_handshake_message(1, client_hello)

    def receive_client_hello(self):

    def send_server_hello(self):
        # Send ServerHello message
        server_hello = b"ServerHello"
        self.send_handshake_message(2, server_hello)

    def receive_server_hello(self):

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

    def receive_client_key_exchange(self):
    

