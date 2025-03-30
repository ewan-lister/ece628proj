import threading
import os
import struct
import time
import logging
from typing import Dict, Optional
from projectclasses.tcp import TCP
from projectclasses.tls import TLS
from projectclasses.crypto import Certificate

class Server:

    RSA_SUITE = "TLS_RSA_WITH_AES_256_CBC_SHA256"
    DHE_SUITE = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"

    CIPHER_SUITE_MAP = {
        RSA_SUITE: 0x003D,
        DHE_SUITE: 0x006B
    }

    def __init__(self, host: str, port: int, supported_suites: str = None):
        self.tcp = TCP(host, port)
        self.tls_connections: Dict[int, TLS] = {}
        self.running = False
        self.supported_suites = supported_suites
        self.server_random = None
        self.clients_lock = threading.Lock()
        self.logger = logging.getLogger('Server')
        
        # Initialize certificate but don't use it yet
        self.certificate = Certificate()
        self.certificate.generate_keys()
        self.certificate.generate_certificate(
            subject_name=f"TLS Server {host}:{port}",
            issuer_name=f"TLS Server CA"
        )

    def start(self):
        """Initialize and start the server"""
        try:
            self.tcp.connect(is_server=True)
            self.running = True
            self.logger.info("Server started and listening")
            
            # Accept clients in a loop
            while self.running:
                self.accept()
        except Exception as e:
            self.logger.error(f"Server error: {e}")
            self.close()
            raise

    def accept(self) -> Optional[int]:
        """Accept new client and perform TLS handshake"""
        try:
            # Accept TCP connection
            client_sock, client_addr = self.tcp.accept()
            client_id = id(client_sock)
            
            # Create TLS instance for this client
            with self.clients_lock:
                tls = TLS(self.tcp, client_id, self.supported_suites)
                self.tls_connections[client_id] = tls
            
            # Start handshake in new thread
            client_thread = threading.Thread(
                target=self._handle_handshake,
                args=(client_id,),
                name=f"Client-{client_id}"
            )
            client_thread.start()
            
            return client_id
        
        except Exception as e:
            self.logger.error(f"Accept failed: {e}")
            return None
        
    def _handle_handshake(self, client_id: int):
        """Handle TLS handshake for new client"""
        try:
            tls = self.tls_connections[client_id]
            
            # Process ClientHello, generate random, and send ServerHello
            client_random, cipher_suite = tls.receive_client_hello()
            self.server_random = self._generate_server_random()
            tls.send_server_hello(self.server_random)
            
            # Continue with key exchange based on chosen cipher suite
            if cipher_suite == TLS.CIPHER_SUITE_MAP[self.RSA_SUITE]:
                shared_secret = self.rsa_handshake(self.server_random, client_random, tls)
            else:
                shared_secret = self.dhe_handshake(self.server_random, client_random, tls)
            
            # Continue with client handling after handshake
            self.handle_client(client_id)
            
        except Exception as e:
            self.logger.error(f"Handshake failed for client {client_id}: {e}")
            self.close_client(client_id)
    
    def handle_client(self, client_id: int):
        """Handle communication with a specific client"""
        try:
            tls = self.tls_connections[client_id]
            
            # Handle client messages
            while self.running:
                content_type, version, data = tls.receive_tls_record()
                if not data:
                    break
                # Process received data...
                
        except Exception as e:
            self.logger.error(f"Error handling client {client_id}: {e}")
        finally:
            self.close_client(client_id)

    def close_client(self, client_id: int):
        """Close a specific client connection"""
        with self.clients_lock:
            if client_id in self.tls_connections:
                del self.tls_connections[client_id]
                self.tcp.close_connection(client_id)

    def close(self):
        """Shutdown the server"""
        self.running = False
        with self.clients_lock:
            for client_id in list(self.tls_connections.keys()):
                self.close_client(client_id)
        self.tcp.close()
        self.logger.info("Server shutdown complete")


    def _generate_server_random(self) -> bytes:
        """Generate the server random (32 bytes: 4 byte timestamp + 28 random bytes)"""
        timestamp = struct.pack("!I", int(time.time()))
        random_bytes = os.urandom(28)
        return timestamp + random_bytes
    
    def rsa_handshake(self, client_random, server_random, tls):
        """Perform RSA handshake"""
        # Placeholder for RSA handshake logic

        # send server certificate
        tls.send_server_certificate(self.certificate)
        # no ServerKeyExchange for RSA
        # send certificate request
        tls.send_certificate_request()
        # send ServerHelloDone

        client_certificate = tls.receive_client_certificate()
        valid, client_signing_key = tls.verify_certificate(client_certificate)
        if not valid:
            raise Exception("Invalid server certificate")
        

    # def dhe_handshake(self, random):
    #     """Perform DHE handshake"""
    #     # Placeholder for DHE handshake logic
    #     pass
