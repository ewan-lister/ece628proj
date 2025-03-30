import struct
import logging
from projectclasses.tcp import TCP
from typing import Optional, Dict
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
import datetime

class TLS:
    CIPHER_SUITE_MAP = {
        "TLS_RSA_WITH_AES_256_CBC_SHA256": 0x003D,
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": 0x006B
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
        self.supported_suites = supported_suites

    def send_handshake_message(self, handshake_type, message):
        # Handshake header: [Handshake Type (1 byte)] + [Length (3 bytes)]
        header = struct.pack("!B3s", handshake_type, len(message).to_bytes(3, 'big'))
        print("4")
        version = (3, 3)  # TLS 1.2)
        content_type = 22 # Handshake type
        self.send_tls_record(content_type, version, header + message) 
    
    def receive_handshake_message(self, expected_type: int = None) -> tuple:
        """Receive and parse a TLS handshake message
        Args:
            expected_type (int, optional): Expected handshake message type
        Returns:
            tuple: (msg_type, msg_data) - (handshake type, message payload)
        """
        content_type, version, payload = self.receive_tls_record()
        
        if content_type != 22:  # Handshake type
            raise ValueError(f"Unexpected record type: {content_type}")
        
        # Parse handshake header
        if len(payload) < 4:
            raise ValueError("Handshake message too short")
        
        msg_type = payload[0]
        msg_len = int.from_bytes(payload[1:4], 'big')
        
        if expected_type is not None and msg_type != expected_type:
            raise ValueError(f"Expected handshake type {expected_type}, got {msg_type}")
        
        # Verify message length
        if len(payload) - 4 != msg_len:
            raise ValueError(f"Message length mismatch: expected {msg_len}, got {len(payload)-4}")
        
        # Extract message data (skip header)
        msg_data = payload[4:]
        
        self.logger.debug(f"Received handshake message:")
        self.logger.debug(f"- Type: {msg_type}")
        self.logger.debug(f"- Length: {msg_len}")
        
        return msg_type, msg_data

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
        record = struct.pack('!BHH', 
            content_type,      # 1 byte (Content Type)
            (version[0] << 8) | version[1],  # 2 bytes (TLS Version)
            len(payload)       # 2 bytes (Payload Length)
        ) 
        record = record + payload
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
    def negotiate_cipher_suites(self, client_hello):
        """
        Parse ClientHello and negotiate cipher suite
        Args:
            client_hello (bytes): Raw ClientHello message payload
        Returns:
            int: Chosen cipher suite value
        """
        # Skip version (2 bytes) + client random (32 bytes)
        offset = 34
        
        # Skip session ID
        session_id_length = client_hello[offset]
        offset += 1 + session_id_length
        
        # Parse cipher suites length
        cipher_suites_length = int.from_bytes(client_hello[offset:offset+2], 'big')
        offset += 2
        
        # Debug log the raw bytes
        self.logger.debug(f"Cipher suites bytes: {client_hello[offset:offset+cipher_suites_length].hex()}")
        
        # Extract client's cipher suites - each suite is 2 bytes
        client_suites = []
        end_offset = offset + cipher_suites_length
        while offset < end_offset:
            suite = int.from_bytes(client_hello[offset:offset+2], 'big')
            print(suite)
            client_suites.append(suite)
            offset += 2
        # Find common suite
        supported_suites = [self.CIPHER_SUITE_MAP[suite] for suite in self.supported_suites]
        self.logger.debug(f"Server supported suites: {[hex(s) for s in supported_suites]}")
        self.logger.debug(f"Client offered suites: {[hex(s) for s in client_suites]}")
        
        for suite in client_suites:
            if (suite in supported_suites):
                self.chosen_cipher = suite
                self.logger.debug(f"Negotiated cipher suite: {hex(suite)}")
                return suite
                
        raise ValueError("No common cipher suite found")
    
    def send_client_hello(self, client_random):
        """Send ClientHello message with specified cipher suites"""
        # Protocol Version (TLS 1.2)
        version = struct.pack("!BB", 3, 3)

        # Session ID (empty)
        session_id = struct.pack("!B", 0)

        # Cipher Suites
        # First collect all cipher suite values
        supported_suite_bytes = b""
        for suite_name in self.supported_suites:
            suite_value = self.CIPHER_SUITE_MAP[suite_name]
            supported_suite_bytes += struct.pack("!H", suite_value)  # Each suite as 2 bytes
        
        # Total length of all cipher suites
        cipher_suites = struct.pack("!H", len(supported_suite_bytes)) + supported_suite_bytes
        
        # Debug print to verify format
        print(f"Cipher suites (hex): {cipher_suites.hex()}")
        
        # Compression Methods (null only)
        compression = struct.pack("!BB", 1, 0)
        
        client_hello = (
            version +
            client_random +
            session_id +
            cipher_suites +
            compression
        )
        self.send_handshake_message(1, client_hello)

    def receive_client_hello(self):
        """Receive and parse ClientHello message
        Returns:
            tuple: (client_random, chosen_cipher_suite)
        """
        msg_type, hello_data = self.receive_handshake_message(expected_type=1)
        
        if len(hello_data) < 34:  # Minimum length for version + random
            raise ValueError("ClientHello too short")
        
        # Extract client version
        client_version = (hello_data[0], hello_data[1])
        if client_version != (3, 3):  # TLS 1.2
            raise ValueError(f"Unsupported TLS version: {client_version}")
        
        # Extract client random
        client_random = hello_data[2:34]
        
        # Parse remaining fields
        chosen_cipher_suite = self.negotiate_cipher_suites(hello_data)
        
        self.client_random = client_random
        self.chosen_cipher = chosen_cipher_suite
        
        self.logger.debug(f"Received ClientHello:")
        self.logger.debug(f"- Client Random: {client_random.hex()}")
        self.logger.debug(f"- Chosen Cipher: {hex(chosen_cipher_suite)}")
        
        return client_random, chosen_cipher_suite

    def send_server_hello(self, server_random):
        """Send ServerHello message
        Args:
            server_random (bytes): 32-byte server random value
        """
        # Protocol Version (TLS 1.2)
        version = struct.pack("!BB", 3, 3)
        
        # Session ID (empty for new session)
        session_id = struct.pack("!B", 0)
        
        # Selected Cipher Suite (2 bytes)
        if not self.chosen_cipher:
            raise ValueError("No cipher suite chosen")
        cipher_suite = struct.pack("!H", self.chosen_cipher)
        
        # Compression Method (null)
        compression = struct.pack("!B", 0)
        
        # Construct ServerHello
        server_hello = (
            version +
            server_random +
            session_id +
            cipher_suite +
            compression
        )
        
        self.server_random = server_random
        self.logger.debug(f"Sending ServerHello:")
        self.logger.debug(f"- Server Random: {server_random.hex()}")
        self.logger.debug(f"- Chosen Cipher: {hex(self.chosen_cipher)}")
        
        # Send with handshake type 2 (ServerHello)
        self.send_handshake_message(2, server_hello)
    
    def receive_server_hello(self):
        """Receive and parse ServerHello message
        Returns:
            tuple: (server_random, chosen_cipher_suite)
        """
        msg_type, hello_data = self.receive_handshake_message(expected_type=2)
        
        if len(hello_data) < 38:  # Minimum length for version + random + session_id_length
            raise ValueError("ServerHello too short")
        
        # Extract server version and validate
        server_version = (hello_data[0], hello_data[1])
        if server_version != (3, 3):  # TLS 1.2
            raise ValueError(f"Unsupported TLS version: {server_version}")
        
        # Extract server random
        server_random = hello_data[2:34]
        
        # Skip session ID and get cipher suite
        session_id_length = hello_data[34]
        offset = 35 + session_id_length
        
        if len(hello_data) < offset + 2:
            raise ValueError("ServerHello truncated")
        chosen_cipher = int.from_bytes(hello_data[offset:offset+2], 'big')
        
        self.server_random = server_random
        self.chosen_cipher = chosen_cipher
        
        self.logger.debug(f"Received ServerHello:")
        self.logger.debug(f"- Server Random: {server_random.hex()}")
        self.logger.debug(f"- Chosen Cipher: {hex(chosen_cipher)}")
        
        return server_random, chosen_cipher

    def send_server_certificate(self, certificate):
        """Send Certificate message containing server's certificate
        Args:
            certificate (Certificate): Server's certificate object
        """
        # Get the certificate in DER format
        cert_bytes = certificate.certificate.public_bytes(serialization.Encoding.DER)
        
        # Certificate message format:
        # 3-byte length of all certificates
        # For each certificate:
        #   3-byte length of certificate
        #   certificate data
        
        # Single certificate case:
        cert_length = len(cert_bytes)
        cert_length_bytes = struct.pack("!3s", cert_length.to_bytes(3, 'big'))
        
        # Total length is 3 + cert_length (3 for the length field itself)
        total_length = cert_length + 3
        total_length_bytes = struct.pack("!3s", total_length.to_bytes(3, 'big'))
        
        certificate_message = (
            total_length_bytes +  # Length of entire certificate list
            cert_length_bytes +   # Length of this certificate
            cert_bytes           # The certificate itself
        )
        
        self.logger.debug(f"Sending Certificate:")
        self.logger.debug(f"- Certificate length: {cert_length}")
        self.logger.debug(f"- Total message length: {total_length}")
        
        # Send with handshake type 11 (Certificate)
        self.send_handshake_message(11, certificate_message)

    def receive_server_certificate(self):
        """Receive and parse server Certificate message
        Returns:
            bytes: The DER-encoded certificate
        """
        msg_type, cert_data = self.receive_handshake_message(expected_type=11)
        
        # Get total length of certificate list
        if len(cert_data) < 3:
            raise ValueError("Certificate message too short")
        total_length = int.from_bytes(cert_data[0:3], 'big')
        
        # Parse first certificate
        if len(cert_data) < 6:
            raise ValueError("No certificate found")
        cert_length = int.from_bytes(cert_data[3:6], 'big')
        
        certificate = cert_data[6:6+cert_length]
        if len(certificate) != cert_length:
            raise ValueError("Certificate data truncated")
        
        self.logger.debug(f"Received Certificate:")
        self.logger.debug(f"- Total length: {total_length}")
        self.logger.debug(f"- Certificate length: {cert_length}")
        
        return certificate
    
    def send_server_key_exchange(self):
        # Send ServerKeyExchange message
        key_exchange = b"ServerKeyExchange"
        self.send_handshake_message(12, key_exchange)
    
    def receive_server_key_exchange(self):
        # Receive ServerKeyExchange message
        _, _, key_exchange = self.receive_tls_record()
        return key_exchange
    
    def send_certificate_request(self):
        """Send CertificateRequest message
        Specifies acceptable certificate types and signature algorithms
        """
        # Certificate types (1 byte length + types)
        # Only RSA (1) supported for this implementation
        cert_types = struct.pack("!BB", 1, 1)  # 1 type, type RSA=1
        
        # Supported signature algorithms (2 bytes length + algorithms)
        # Only SHA256 with RSA (0x0401) for this implementation
        sig_algs = struct.pack("!HH", 2, 0x0401)  # 2 bytes length, RSA+SHA256
        
        # Distinguished names length (2 bytes) - empty list
        dn_length = struct.pack("!H", 0)
        
        # Construct CertificateRequest message
        cert_request = (
            cert_types +
            sig_algs +
            dn_length
        )
        
        self.logger.debug("Sending CertificateRequest:")
        self.logger.debug("- Certificate types: RSA")
        self.logger.debug("- Signature algorithms: RSA+SHA256")
        
        # Send with handshake type 13 (CertificateRequest)
        self.send_handshake_message(13, cert_request)
    
    def receive_certificate_request(self):
        """Receive and parse CertificateRequest message
        Returns:
            tuple: (cert_types, sig_algs)
        """
        msg_type, request_data = self.receive_handshake_message(expected_type=13)
        
        # Parse certificate types
        if len(request_data) < 1:
            raise ValueError("CertificateRequest truncated")
        cert_types_length = request_data[0]
        cert_types = list(request_data[1:1+cert_types_length])
        offset = 1 + cert_types_length
        
        # Parse signature algorithms
        if len(request_data) < offset + 2:
            raise ValueError("Missing signature algorithms")
        sig_algs_length = int.from_bytes(request_data[offset:offset+2], 'big')
        offset += 2
        
        sig_algs = []
        sig_algs_end = offset + sig_algs_length
        while offset < sig_algs_end:
            if len(request_data) < offset + 2:
                raise ValueError("Signature algorithm data truncated")
            sig_alg = int.from_bytes(request_data[offset:offset+2], 'big')
            sig_algs.append(sig_alg)
            offset += 2
        
        self.logger.debug("Received CertificateRequest:")
        self.logger.debug(f"- Certificate types: {[hex(t) for t in cert_types]}")
        self.logger.debug(f"- Signature algorithms: {[hex(a) for a in sig_algs]}")
        
        return cert_types, sig_algs
    
    def send_server_hello_done(self):
        """Send ServerHelloDone message
        An empty message indicating server is done with handshake negotiation"""
        # ServerHelloDone is an empty message, just send the header
        self.logger.debug("Sending ServerHelloDone")
        self.send_handshake_message(14, b'')  # Type 14 for ServerHelloDone

    def receive_server_hello_done(self):
        """Receive and verify ServerHelloDone message"""
        msg_type, hello_done_data = self.receive_handshake_message(expected_type=14)
        
        # ServerHelloDone should be empty
        if hello_done_data:
            raise ValueError(f"ServerHelloDone should be empty, got {len(hello_done_data)} bytes")
        
        self.logger.debug("Received ServerHelloDone")

    def client_key_exchange(self):
        # Send ClientKeyExchange message
        key_exchange = b"ClientKeyExchange"
        self.send_handshake_message(16, key_exchange)

    #def receive_client_key_exchange(self):

    def verify_certificate(self, cert_bytes, issuer_cert=None):
        """Verify a received certificate and extract its public key
        Args:
            cert_bytes (bytes): DER-encoded certificate to verify
            issuer_cert (Certificate, optional): Issuer's certificate for verification
        Returns:
            tuple: (bool, rsa.RSAPublicKey or None) - (is_valid, public_key)
        """
        try:
            # Load the received certificate
            cert = x509.load_der_x509_certificate(cert_bytes)
            
            # Basic certificate checks
            now = datetime.datetime.utcnow()
            if now < cert.not_valid_before:
                self.logger.error("Certificate not yet valid")
                return False, None
            if now > cert.not_valid_after:
                self.logger.error("Certificate has expired")
                return False, None
                
            # Extract public key and verify it's RSA
            public_key = cert.public_key()
            if not isinstance(public_key, rsa.RSAPublicKey):
                self.logger.error("Certificate does not contain an RSA public key")
                return False, None
                
            if issuer_cert:
                # Verify certificate signature using issuer's public key
                try:
                    issuer_cert.certificate.public_key().verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm
                    )
                except InvalidSignature:
                    self.logger.error("Certificate signature verification failed")
                    return False, None
            else:
                # Self-signed certificate case
                try:
                    public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm
                    )
                except InvalidSignature:
                    self.logger.error("Self-signed certificate verification failed")
                    return False, None
            
            self.logger.debug("Certificate verification successful")
            self.logger.debug(f"Public key modulus: {public_key.public_numbers().n}")
            self.logger.debug(f"Public key exponent: {public_key.public_numbers().e}")
            
            return True, public_key
            
        except Exception as e:
            self.logger.error(f"Certificate verification error: {e}")
            return False, None
