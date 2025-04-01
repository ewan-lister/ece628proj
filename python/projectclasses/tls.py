import struct
import logging
import datetime
import os
from projectclasses.tcp import TCP
from typing import Optional, Dict
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import hmac as hmac_stdlib  # For constant-time comparison
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

class TLS:
    CIPHER_SUITE_MAP = {
        "TLS_RSA_WITH_AES_256_CBC_SHA256": 0x003D,
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": 0x006B
    }

    HANDSHAKE_TYPES = {
        1: "ClientHello",
        2: "ServerHello",
        11: "Certificate",
        12: "ServerKeyExchange",
        13: "CertificateRequest",
        14: "ServerHelloDone",
        15: "CertificateVerify",
        16: "ClientKeyExchange",
        20: "Finished"
    }

    def __init__(self, tcp_connection, connection_id: Optional[int] = None, 
                 supported_suites: Optional[list] = None):
        self.tcp = tcp_connection
        self.connection_id = connection_id
        self.logger = logging.getLogger("TLS")
        self.chosen_cipher = None
        self.client_random = None
        self.server_random = None
        # Default to supporting all suites if none specified
        self.supported_suites = supported_suites
        self.handshake_messages = bytearray()  # Store all handshake messages

    def send_handshake_message(self, handshake_type, message):
        """Send TLS handshake message"""
        # Create the full handshake message
        header = struct.pack("!B3s", handshake_type, len(message).to_bytes(3, 'big'))
        full_message = header + message
        
        # Store for CertificateVerify
        self.handshake_messages.extend(full_message)
        
        # Send the message
        version = (3, 3)  # TLS 1.2
        content_type = 22  # Handshake type
        self.send_tls_record(content_type, version, full_message)
        
        # Log after successful send
        msg_name = self.HANDSHAKE_TYPES.get(handshake_type, f"Unknown({handshake_type})")
        self.logger.info(f"Sent {msg_name}")
        self.logger.debug(f"- Length: {len(message)}")

    def receive_handshake_message(self, expected_type: int = None) -> tuple:
        """Receive and parse TLS handshake message"""
        content_type, version, payload = self.receive_tls_record()
        
        if content_type != 22:  # Handshake type
            raise ValueError(f"Expected handshake message (type 22), got type {content_type}")
        
        # Parse handshake header
        if len(payload) < 4:
            raise ValueError("Handshake message too short")
        
        msg_type = payload[0]
        msg_len = int.from_bytes(payload[1:4], 'big')
        
        # Verify expected type
        msg_name = self.HANDSHAKE_TYPES.get(msg_type, f"Unknown({msg_type})")
        if expected_type is not None and msg_type != expected_type:
            expected_name = self.HANDSHAKE_TYPES.get(expected_type, f"Unknown({expected_type})")
            raise ValueError(f"Expected {expected_name}, got {msg_name}")
        
        # Verify message length
        if len(payload) - 4 != msg_len:
            raise ValueError(f"Message length mismatch: expected {msg_len}, got {len(payload)-4}")
        
        # Extract message data
        msg_data = payload[4:]
        
        # Store the full message
        full_message = struct.pack("!B3s", msg_type, len(msg_data).to_bytes(3, 'big')) + msg_data
        self.handshake_messages.extend(full_message)
        
        # Log after successful processing
        self.logger.info(f"Received {msg_name}")
        self.logger.debug(f"- Length: {msg_len}")
        
        return msg_type, msg_data

    def send_tls_record(self, content_type: int, version: tuple, payload: bytes):
        """Send TLS record"""
        record = struct.pack('!BHH', 
            content_type,
            (version[0] << 8) | version[1],
            len(payload)
        ) + payload
        self.tcp.send(record, self.connection_id)
        self.logger.debug(f"Sent {len(record)} bytes")

    def receive_tls_record(self):
        """Receive TLS record"""
        header = self.tcp.receive(5, self.connection_id)
        if len(header) < 5:
            raise ConnectionError("Incomplete TLS header received")

        content_type = header[0]
        version = (header[1], header[2])
        length = int.from_bytes(header[3:5], byteorder='big')

        payload = self.tcp.receive(length, self.connection_id)
        if len(payload) < length:
            raise ConnectionError(f"Incomplete payload received: {len(payload)} < {length}")

        self.logger.debug(f"Received TLS record type {content_type} ({length} bytes)")
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
        while (offset < end_offset):
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

        self.client_random = client_random

        # Cipher Suites
        # First collect all cipher suite values
        supported_suite_bytes = b""
        for suite_name in self.supported_suites:
            suite_value = self.CIPHER_SUITE_MAP[suite_name]
            supported_suite_bytes += struct.pack("!H", suite_value)  # Each suite as 2 bytes
        
        # Total length of all cipher suites
        cipher_suites = struct.pack("!H", len(supported_suite_bytes)) + supported_suite_bytes
        
        # Debug print to verify format
        #print(f"Cipher suites (hex): {cipher_suites.hex()}")
        
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
        
        if (len(hello_data) < 34):  # Minimum length for version + random
            raise ValueError("ClientHello too short")
        
        # Extract client version
        client_version = (hello_data[0], hello_data[1])
        if (client_version != (3, 3)):  # TLS 1.2
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
        
        if (len(hello_data) < 38):  # Minimum length for version + random + session_id_length
            raise ValueError("ServerHello too short")
        
        # Extract server version and validate
        server_version = (hello_data[0], hello_data[1])
        if (server_version != (3, 3)):  # TLS 1.2
            raise ValueError(f"Unsupported TLS version: {server_version}")
        
        # Extract server random
        server_random = hello_data[2:34]
        
        # Skip session ID and get cipher suite
        session_id_length = hello_data[34]
        offset = 35 + session_id_length
        
        if (len(hello_data) < offset + 2):
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
        if (len(cert_data) < 3):
            raise ValueError("Certificate message too short")
        total_length = int.from_bytes(cert_data[0:3], 'big')
        
        # Parse first certificate
        if (len(cert_data) < 6):
            raise ValueError("No certificate found")
        cert_length = int.from_bytes(cert_data[3:6], 'big')
        
        certificate = cert_data[6:6+cert_length]
        if (len(certificate) != cert_length):
            raise ValueError("Certificate data truncated")
        
        self.logger.debug(f"Received Certificate:")
        self.logger.debug(f"- Total length: {total_length}")
        self.logger.debug(f"- Certificate length: {cert_length}")
        
        return certificate
    
    def send_server_key_exchange_dhe(self, server_private_key, dh_parameters=None):
        """Send ServerKeyExchange with DHE parameters"""
        import time
        start_time = time.time()
        
        # Use provided or generate new parameters
        parameters = dh_parameters or dh.generate_parameters(generator=2, key_size=2048)
        
        # Generate DH parameters
        dh_private_key = parameters.generate_private_key()
        public_numbers = dh_private_key.public_key().public_numbers()
        parameter_numbers = public_numbers.parameter_numbers
        
        # Format message:
        # - p (DH prime)
        # - g (generator)
        # - public key
        p_bytes = parameter_numbers.p.to_bytes((parameter_numbers.p.bit_length() + 7) // 8, 'big')
        g_bytes = parameter_numbers.g.to_bytes((parameter_numbers.g.bit_length() + 7) // 8, 'big')
        pubkey_bytes = public_numbers.y.to_bytes((public_numbers.y.bit_length() + 7) // 8, 'big')
        
        # Sign the parameters
        params_to_sign = p_bytes + g_bytes + pubkey_bytes
        signature = server_private_key.sign(
            params_to_sign,
            asymmetric_padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Store server's DH public key for later
        self.server_dh_public_key = dh_private_key.public_key()
        
        # Construct message with lengths
        message = (
            struct.pack('!H', len(p_bytes)) + p_bytes +
            struct.pack('!H', len(g_bytes)) + g_bytes +
            struct.pack('!H', len(pubkey_bytes)) + pubkey_bytes +
            struct.pack('!H', len(signature)) + signature
        )
        
        self.logger.debug("Sending DHE ServerKeyExchange")
        self.logger.debug(f"- DH prime length: {len(p_bytes)}")
        self.logger.debug(f"- Public key length: {len(pubkey_bytes)}")
        self.logger.debug(f"- Signature length: {len(signature)}")
        
        self.send_handshake_message(12, message)
        return dh_private_key

    def receive_server_key_exchange_dhe(self, server_public_key):
        """Receive and verify DHE ServerKeyExchange"""
        msg_type, key_exchange = self.receive_handshake_message(expected_type=12)
        
        # Parse parameters
        offset = 0
        p_len = int.from_bytes(key_exchange[offset:offset+2], 'big')
        offset += 2
        p = int.from_bytes(key_exchange[offset:offset+p_len], 'big')
        offset += p_len
        
        g_len = int.from_bytes(key_exchange[offset:offset+2], 'big')
        offset += 2
        g = int.from_bytes(key_exchange[offset:offset+g_len], 'big')
        offset += g_len
        
        pubkey_len = int.from_bytes(key_exchange[offset:offset+2], 'big')
        offset += 2
        # Fix: Use correct offset for y value
        y = int.from_bytes(key_exchange[offset:offset+pubkey_len], 'big')
        offset += pubkey_len
        
        sig_len = int.from_bytes(key_exchange[offset:offset+2], 'big')
        offset += 2
        signature = key_exchange[offset:offset+sig_len]
        
        # Verify signature
        params_to_verify = (
            key_exchange[2:2+p_len] +
            key_exchange[2+p_len+2:2+p_len+2+g_len] +
            key_exchange[2+p_len+2+g_len+2:offset-2]
        )
        
        try:
            server_public_key.verify(
                signature,
                params_to_verify,
                asymmetric_padding.PKCS1v15(),
                hashes.SHA256()
            )
        except InvalidSignature:
            raise ValueError("DHE parameters signature verification failed")
        
        # Create DH parameters and public key
        parameter_numbers = dh.DHParameterNumbers(p, g)
        parameters = parameter_numbers.parameters()
        public_numbers = dh.DHPublicNumbers(y, parameter_numbers)
        public_key = public_numbers.public_key()
        
        # Store server's DH public key for later use
        self.server_dh_public_key = public_key
        
        self.logger.debug("Received DHE ServerKeyExchange")
        self.logger.debug(f"- DH prime length: {p_len}")
        self.logger.debug(f"- Public key length: {pubkey_len}")
        self.logger.debug(f"- Y value: {y}")
        
        return parameters, public_key

    def send_client_key_exchange_dhe(self, dh_parameters):
        """Send ClientKeyExchange for DHE
        Args:
            dh_parameters (dh.DHParameters): DH parameters from server
        Returns:
            bytes: The computed shared secret
        """
        # Generate client's DH key pair
        private_key = dh_parameters.generate_private_key()
        public_key = private_key.public_key()
        
        # Get public key bytes
        public_numbers = public_key.public_numbers()
        pubkey_bytes = public_numbers.y.to_bytes((public_numbers.y.bit_length() + 7) // 8, 'big')
        
        # Send public key with length
        message = struct.pack('!H', len(pubkey_bytes)) + pubkey_bytes
        
        self.logger.debug("Sending DHE ClientKeyExchange")
        self.logger.debug(f"- Public key length: {len(pubkey_bytes)}")
        
        self.send_handshake_message(16, message)
        
        # Compute shared secret
        shared_secret = private_key.exchange(self.server_dh_public_key)
        self.premaster_secret = shared_secret
        
        return shared_secret

    def receive_client_key_exchange_dhe(self, server_dh_private_key):
        """Receive ClientKeyExchange for DHE
        Args:
            server_dh_private_key (dh.DHPrivateKey): Server's DH private key
        Returns:
            bytes: The computed shared secret
        """
        msg_type, key_exchange = self.receive_handshake_message(expected_type=16)
        
        # Parse client's public key
        pubkey_len = int.from_bytes(key_exchange[:2], 'big')
        y = int.from_bytes(key_exchange[2:2+pubkey_len], 'big')
        
        # Create client's public key object using the DH parameters from server's key
        dh_params = server_dh_private_key.parameters()
        parameter_numbers = dh_params.parameter_numbers()
        public_numbers = dh.DHPublicNumbers(y, parameter_numbers)
        client_public_key = public_numbers.public_key()
        
        # Compute shared secret
        try:
            shared_secret = server_dh_private_key.exchange(client_public_key)
            self.premaster_secret = shared_secret
            
            self.logger.debug("Received DHE ClientKeyExchange")
            self.logger.debug(f"- Public key length: {pubkey_len}")
            
            return shared_secret
        except Exception as e:
            self.logger.error(f"Error computing shared key: {e}")
            raise ValueError("Error computing shared key.")

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
        if (len(request_data) < 1):
            raise ValueError("CertificateRequest truncated")
        cert_types_length = request_data[0]
        cert_types = list(request_data[1:1+cert_types_length])
        offset = 1 + cert_types_length
        
        # Parse signature algorithms
        if (len(request_data) < offset + 2):
            raise ValueError("Missing signature algorithms")
        sig_algs_length = int.from_bytes(request_data[offset:offset+2], 'big')
        offset += 2
        
        sig_algs = []
        sig_algs_end = offset + sig_algs_length
        while (offset < sig_algs_end):
            if (len(request_data) < offset + 2):
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
        if (hello_done_data):
            raise ValueError(f"ServerHelloDone should be empty, got {len(hello_done_data)} bytes")
        
        self.logger.debug("Received ServerHelloDone")

    def send_rsa_client_key_exchange(self, server_public_key, client_private_key=None):
        """Send ClientKeyExchange message with RSA-encrypted premaster secret
        Args:
            server_public_key (rsa.RSAPublicKey): Server's public key from certificate
            client_private_key (rsa.RSAPrivateKey, optional): Client's private key for signing
        Returns:
            bytes: Generated premaster secret
        """
        # Generate 48-byte premaster secret
        premaster_secret = struct.pack('!BB', 3, 3)  # TLS 1.2
        premaster_secret += os.urandom(46)  # Random bytes
        
        # Encrypt premaster secret with server's public key
        encrypted_secret = server_public_key.encrypt(
            premaster_secret,
            asymmetric_padding.PKCS1v15()
        )
        
        # Format length as 2 bytes
        length = struct.pack('!H', len(encrypted_secret))
        message = length + encrypted_secret
        
        # If client authentication is requested, sign the handshake
        if client_private_key:
            verify_data = self.client_random + self.server_random + premaster_secret
            signature = client_private_key.sign(
                verify_data,
                asymmetric_padding.PKCS1v15(),
                hashes.SHA256()
            )
            # Add signature length and signature to message
            sig_length = struct.pack('!H', len(signature))
            message += sig_length + signature
        
        self.logger.debug("Sending ClientKeyExchange")
        self.logger.debug(f"- Premaster secret length: {len(premaster_secret)}")
        self.logger.debug(f"- Encrypted length: {len(encrypted_secret)}")
        if client_private_key:
            self.logger.debug(f"- Signature length: {len(signature)}")
        
        # Send message
        self.send_handshake_message(16, message)
        
        # Store premaster secret for key derivation
        self.premaster_secret = premaster_secret
        
        # Return the premaster secret
        return premaster_secret

    def receive_rsa_client_key_exchange(self, server_private_key, client_public_key=None):
        """Receive and decrypt ClientKeyExchange message
        Args:
            server_private_key (rsa.RSAPrivateKey): Server's private key for decryption
            client_public_key (rsa.RSAPublicKey, optional): Client's public key for verification
        Returns:
            bytes: Decrypted premaster secret
        """
        msg_type, encrypted_data = self.receive_handshake_message(expected_type=16)
        
        # First 2 bytes are the length
        if (len(encrypted_data) < 2):
            raise ValueError("ClientKeyExchange too short")
        
        length = int.from_bytes(encrypted_data[:2], 'big')
        encrypted_secret = encrypted_data[2:2+length]
        
        if (len(encrypted_secret) != length):
            raise ValueError(f"Encrypted data length mismatch: {len(encrypted_secret)} != {length}")
        
        # Ensure we have a proper RSA private key object
        if not isinstance(server_private_key, rsa.RSAPrivateKey):
            self.logger.error(f"Invalid private key type: {type(server_private_key)}")
            raise TypeError("server_private_key must be an RSA private key object")
        
        # Decrypt premaster secret
        try:
            premaster_secret = server_private_key.decrypt(
                encrypted_secret,
                asymmetric_padding.PKCS1v15()
            )
            self.logger.debug(f"Successfully decrypted premaster secret of length {len(premaster_secret)}")
        except Exception as e:
            self.logger.error(f"Failed to decrypt premaster secret: {e}")
            raise
        
        # Verify signature if client authentication is used
        if client_public_key:
            if (len(encrypted_data) < 2+length+2):
                raise ValueError("Missing signature")
            
            sig_length = int.from_bytes(encrypted_data[2+length:2+length+2], 'big')
            signature = encrypted_data[2+length+2:2+length+2+sig_length]
            
            # Verify the signature
            verify_data = self.client_random + self.server_random + premaster_secret
            try:
                client_public_key.verify(
                    signature,
                    verify_data,
                    asymmetric_padding.PKCS1v15(),
                    hashes.SHA256()
                )
            except InvalidSignature:
                raise ValueError("Client signature verification failed")
        
        # Verify premaster secret format
        if (len(premaster_secret) != 48):
            raise ValueError(f"Invalid premaster secret length: {len(premaster_secret)}")
        if (premaster_secret[:2] != b'\x03\x03'):  # TLS 1.2
            raise ValueError("Invalid protocol version in premaster secret")
        
        self.logger.debug("Received ClientKeyExchange")
        self.logger.debug(f"- Decrypted premaster secret length: {len(premaster_secret)}")
        
        # Store premaster secret for key derivation
        self.premaster_secret = premaster_secret
        return premaster_secret

    def verify_certificate(self, cert_bytes, issuer_cert=None):
        try:
            # Load the received certificate
            cert = x509.load_der_x509_certificate(cert_bytes)
            
            # Basic certificate checks using UTC-aware methods
            now = datetime.datetime.now(datetime.timezone.utc)
            if now < cert.not_valid_before_utc:
                self.logger.error("Certificate not yet valid")
                return False, None
            if now > cert.not_valid_after_utc:
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
                        asymmetric_padding.PKCS1v15(),  # Use asymmetric padding
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
                        asymmetric_padding.PKCS1v15(),  # Use asymmetric padding
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

    def send_client_certificate(self, certificate=None):
        """Send Certificate message containing client's certificate
        Args:
            certificate (Certificate, optional): Client's certificate. If None, sends empty certificate list
        """
        if certificate:
            # Get the certificate in DER format
            cert_bytes = certificate.certificate.public_bytes(serialization.Encoding.DER)
            
            # Format certificate with its 3-byte length
            cert_length = len(cert_bytes)
            cert_length_bytes = struct.pack("!3s", cert_length.to_bytes(3, 'big'))
            cert_data = cert_length_bytes + cert_bytes
            
            # Total length is cert length + 3 (for length field)
            total_length = len(cert_data)
            total_length_bytes = struct.pack("!3s", total_length.to_bytes(3, 'big'))
            
            certificate_message = total_length_bytes + cert_data
            
            self.logger.debug("Sending client Certificate:")
            self.logger.debug(f"- Certificate length: {cert_length}")
            self.logger.debug(f"- Total message length: {total_length}")
        else:
            # Send empty certificate list (3 bytes of zero for the length)
            certificate_message = b'\x00\x00\x00'
            self.logger.debug("Sending empty client Certificate")
        
        # Send with handshake type 11 (Certificate)
        self.send_handshake_message(11, certificate_message)
    
    def receive_client_certificate(self):
        """Receive and parse client Certificate message
        Returns:
            Optional[bytes]: The DER-encoded certificate, or None if client sent empty certificate list
        """
        msg_type, cert_data = self.receive_handshake_message(expected_type=11)
        
        # Get total length of certificate list
        if (len(cert_data) < 3):
            raise ValueError("Certificate message too short")
        
        total_length = int.from_bytes(cert_data[0:3], 'big')
        
        # Check for empty certificate list
        if (total_length == 0):
            self.logger.debug("Received empty client Certificate")
            return None
        
        # Parse first certificate
        if (len(cert_data) < 6):
            raise ValueError("Certificate data truncated")
        
        cert_length = int.from_bytes(cert_data[3:6], 'big')
        
        # Extract certificate data
        certificate = cert_data[6:6+cert_length]
        if (len(certificate) != cert_length):
            raise ValueError("Certificate data truncated")
        
        self.logger.debug("Received client Certificate:")
        self.logger.debug(f"- Total length: {total_length}")
        self.logger.debug(f"- Certificate length: {cert_length}")
        
        return certificate

    def send_change_cipher_spec(self):
        """Send ChangeCipherSpec message"""
        self.logger.debug("Sending ChangeCipherSpec")
        # Single byte with value 1
        message = bytes([1])
        # ChangeCipherSpec is a different content type (20), not a handshake message
        self.send_tls_record(20, (3,3), message)  # 20 is ChangeCipherSpec content type

    def receive_change_cipher_spec(self):
        """Receive and verify ChangeCipherSpec message"""
        content_type, version, message = self.receive_tls_record()
        if (content_type != 20):  # ChangeCipherSpec content type
            raise ValueError(f"Expected ChangeCipherSpec, got type {content_type}")
        if (message != bytes([1])):
            raise ValueError("Invalid ChangeCipherSpec message")
        self.logger.debug("Received ChangeCipherSpec")

    def send_certificate_verify(self, client_private_key):
        """Send CertificateVerify message
        Args:
            client_private_key (rsa.RSAPrivateKey): Client's private key for signing
        """
        self.logger.info("Sending CertificateVerify message")
        
        # Important: Remove the current CertificateVerify message from handshake_messages
        # since it shouldn't be included in its own hash
        current_messages = self.handshake_messages[:]
        
        # Hash of all previous handshake messages
        handshake_hash = hashes.Hash(hashes.SHA256())
        handshake_hash.update(current_messages)
        digest = handshake_hash.finalize()
        
        # Now we can log the digest length
        self.logger.debug(f"- Handshake hash length: {len(digest)}")
        
        # Sign the hash
        signature = client_private_key.sign(
            digest,
            asymmetric_padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Format message: signature length (2 bytes) + signature
        message = struct.pack('!H', len(signature)) + signature
        
        self.logger.debug(f"- Signature length: {len(signature)}")
        self.logger.debug(f"- Handshake messages hash: {digest.hex()}")
        
        # Send with handshake type 15 (CertificateVerify)
        self.send_handshake_message(15, message)

    def receive_certificate_verify(self, client_public_key):
        self.logger.info("Processing CertificateVerify message")
        msg_type, verify_data = self.receive_handshake_message(expected_type=15)
        
        # Get the handshake messages up to but not including this CertificateVerify
        verify_messages = self.handshake_messages[:-4-len(verify_data)]
        
        # Parse signature length and signature
        if (len(verify_data) < 2):
            raise ValueError("CertificateVerify too short")
        
        sig_length = int.from_bytes(verify_data[:2], 'big')
        signature = verify_data[2:2+sig_length]
        
        if (len(signature) != sig_length):
            raise ValueError(f"Signature length mismatch: {len(signature)} != {sig_length}")
        
        # Compute hash of previous handshake messages
        handshake_hash = hashes.Hash(hashes.SHA256())
        handshake_hash.update(verify_messages)
        digest = handshake_hash.finalize()
        
        self.logger.debug(f"Verifying CertificateVerify")
        self.logger.debug(f"- Handshake messages hash: {digest.hex()}")
        self.logger.debug(f"- Signature length: {len(signature)}")
        
        try:
            client_public_key.verify(
                signature,
                digest,
                asymmetric_padding.PKCS1v15(),
                hashes.SHA256()
            )
            self.logger.debug("CertificateVerify signature verified successfully")
        except InvalidSignature:
            self.logger.error("CertificateVerify signature verification failed")
            raise ValueError("CertificateVerify signature verification failed")
        except Exception as e:
            self.logger.error(f"Error verifying CertificateVerify: {e}")
            raise

    def derive_keys(self, is_client: bool):
        """Derive session keys from premaster secret and random values"""
        if not all([self.premaster_secret, self.client_random, self.server_random]):
            raise ValueError("Missing secrets for key derivation")

        # First derive master secret
        label = b"master secret"
        seed = self.client_random + self.server_random
        self.master_secret = self._prf(self.premaster_secret, label, seed, 48)

        # Then derive key block
        label = b"key expansion"
        seed = self.server_random + self.client_random
        key_block = self._prf(self.master_secret, label, seed, 160)

        # Split and assign keys
        offset = 0
        self.write_mac_key = key_block[offset:offset+32] if is_client else key_block[offset+32:offset+64]
        self.read_mac_key = key_block[offset+32:offset+64] if is_client else key_block[offset:offset+32]
        offset += 64
        self.write_key = key_block[offset:offset+32] if is_client else key_block[offset+32:offset+64]
        self.read_key = key_block[offset+32:offset+64] if is_client else key_block[offset:offset+32]
        offset += 64
        self.write_iv = key_block[offset:offset+16] if is_client else key_block[offset+16:offset+32]
        self.read_iv = key_block[offset+16:offset+32] if is_client else key_block[offset:offset+16]

        # Log after successful derivation
        self.logger.info("Session keys derived successfully")
        self.logger.debug(f"- Master secret length: {len(self.master_secret)}")
        self.logger.debug(f"- Write/Read key length: {len(self.write_key)}")

    def send_finished(self):
        """Send Finished message
        Must be sent after ChangeCipherSpec and uses derived keys
        """
        # Generate verify data
        label = b"client finished" if self.connection_id is None else b"server finished"
        handshake_hash = hashes.Hash(hashes.SHA256())
        handshake_hash.update(self.handshake_messages)
        digest = handshake_hash.finalize()
        
        verify_data = self._prf(self.master_secret, label, digest, 12)
        
        self.logger.debug("Sending Finished message")
        self.logger.debug(f"- Verify data length: {len(verify_data)}")
        
        # Send with handshake type 20 (Finished)
        # This will be encrypted using the new keys
        self.send_handshake_message(20, verify_data)

    def receive_finished(self):
        """Receive and verify Finished message
        Must be received after ChangeCipherSpec and uses derived keys
        """
        msg_type, verify_data = self.receive_handshake_message(expected_type=20)
        
        # Generate expected verify data
        label = b"server finished" if self.connection_id is None else b"client finished"
        handshake_hash = hashes.Hash(hashes.SHA256())
        handshake_hash.update(self.handshake_messages[:-4-len(verify_data)])
        digest = handshake_hash.finalize()
        
        expected_verify = self._prf(self.master_secret, label, digest, 12)
        
        if (verify_data != expected_verify):
            raise ValueError("Finished message verification failed")
        
        self.logger.debug("Finished message verified successfully")

    def _prf(self, secret, label, seed, length):
        """TLS 1.2 PRF using HMAC-SHA256
        Args:
            secret (bytes): Key for HMAC
            label (bytes): Label string
            seed (bytes): Seed value
            length (int): Desired output length in bytes
        Returns:
            bytes: Pseudorandom output of desired length
        """
        from cryptography.hazmat.primitives import hmac
        
        def p_hash(secret, seed, length):
            """HMAC-based expansion function"""
            output = bytearray()
            a = seed
            
            while (len(output) < length):
                h = hmac.HMAC(secret, hashes.SHA256())
                h.update(a)
                a = h.finalize()
                
                h = hmac.HMAC(secret, hashes.SHA256())
                h.update(a + seed)
                output.extend(h.finalize())
            
            return bytes(output[:length])
        
        return p_hash(secret, label + seed, length)

    def send_application_data(self, data):
        """Send encrypted application data"""
        self.logger.info("Sending encrypted application data")
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif not isinstance(data, bytes):
            raise TypeError("Data must be bytes or str")

        self.logger.debug(f"- Plaintext: {data}")
        self.logger.debug(f"- Plaintext length: {len(data)} bytes")

        # Generate random IV for this message
        message_iv = os.urandom(16)
        self.logger.debug(f"- Generated IV: {message_iv.hex()}")

        # Create cipher with unique IV
        cipher = Cipher(
            algorithms.AES256(self.write_key),
            modes.CBC(message_iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # Add padding and encrypt
        padder = symmetric_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        self.logger.debug(f"- Ciphertext: {ciphertext.hex()}")

        # Generate MAC
        mac = hmac.HMAC(self.write_mac_key, hashes.SHA256(), backend=default_backend())
        mac.update(message_iv + ciphertext)
        mac_value = mac.finalize()
        self.logger.debug(f"- MAC: {mac_value.hex()}")

        # Send IV + encrypted data + MAC
        full_message = message_iv + ciphertext + mac_value
        self.send_tls_record(23, (3,3), full_message)
        self.logger.debug(f"Sent {len(full_message)} bytes")

    def receive_application_data(self) -> bytes:
        """Receive and decrypt application data"""
        self.logger.info("Receiving encrypted application data")
        content_type, version, encrypted_data = self.receive_tls_record()
        
        if content_type != 23:  # Application Data
            raise ValueError(f"Expected application data, got type {content_type}")
        
        self.logger.debug(f"- Received {len(encrypted_data)} bytes of encrypted data")
        self.logger.debug(f"- Full encrypted data: {encrypted_data.hex()}")
        
        # Extract IV, ciphertext and MAC
        message_iv = encrypted_data[:16]  # First 16 bytes are IV
        ciphertext = encrypted_data[16:-32]  # Middle portion is ciphertext
        received_mac = encrypted_data[-32:]  # Last 32 bytes are MAC
        
        self.logger.debug(f"- IV: {message_iv.hex()}")
        self.logger.debug(f"- Ciphertext: {ciphertext.hex()}")
        self.logger.debug(f"- Received MAC: {received_mac.hex()}")
        
        # Verify MAC
        mac = hmac.HMAC(self.read_mac_key, hashes.SHA256(), backend=default_backend())
        mac.update(message_iv + ciphertext)  # Include IV in MAC calculation
        calculated_mac = mac.finalize()
        
        # Use constant-time comparison
        if not hmac_stdlib.compare_digest(calculated_mac, received_mac):
            raise ValueError("MAC verification failed")
        
        # Decrypt data using received IV
        cipher = Cipher(
            algorithms.AES256(self.read_key),
            modes.CBC(message_iv),  # Use message IV instead of static read_iv
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = symmetric_padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        self.logger.debug(f"- Decrypted {len(data)} bytes")
        return data

    def send_alert(self, level, description):
        """Send TLS alert message
        Args:
            level (int): Alert level (1 = warning, 2 = fatal)
            description (int): Alert description (0 = close_notify)
        """
        alert = struct.pack('!BB', level, description)
        self.send_tls_record(21, (3,3), alert)  # 21 is Alert content type
