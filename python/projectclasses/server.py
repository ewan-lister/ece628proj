import threading
import logging
from typing import Dict, Optional
from projectclasses.tcp import TCP
from projectclasses.tls import TLS

class Server:
    def __init__(self, host: str, port: int):
        self.tcp = TCP(host, port)
        self.tls_connections: Dict[int, TLS] = {}
        self.running = False
        self.clients_lock = threading.Lock()
        self.logger = logging.getLogger('Server')

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
                tls = TLS(self.tcp, client_id)
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
            
            # Receive ClientHello
            content_type, version, client_hello = tls.receive_tls_record()
            if content_type != 22:  # Handshake type
                raise ValueError("Expected ClientHello")
                
            # Process ClientHello and send ServerHello
            cipher_suite = tls.negotiate_cipher_suites(client_hello)
            tls.send_server_hello(cipher_suite)
            
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
