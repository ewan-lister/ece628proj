import struct
import logging
from projectclasses.tcp import TCP

class TLS:
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
