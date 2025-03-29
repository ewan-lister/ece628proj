import socket
import logging
from typing import Tuple, Optional

class TCP:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = {}  # Store multiple client connections
        
        # Logger setup
        self.logger = logging.getLogger('TCP')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def connect(self, is_server=False):
        if is_server:
            # Enable address reuse
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)  # Allow multiple pending connections
            self.logger.info(f"Server listening on {self.host}:{self.port}")
        else:
            self.socket.connect((self.host, self.port))
            self.logger.info(f"Client connected to {self.host}:{self.port}")

    def accept(self) -> Tuple[socket.socket, Tuple[str, int]]:
        """Accept a new client connection"""
        if not self.socket:
            raise RuntimeError("Server socket not initialized")
            
        client_sock, client_addr = self.socket.accept()
        connection_id = id(client_sock)
        self.connections[connection_id] = {
            'socket': client_sock,
            'address': client_addr
        }
        self.logger.info(f"New connection from {client_addr}")
        return client_sock, client_addr
    
    def send(self, data: bytes, connection_id: Optional[int] = None):
        """Send data to specific client or through client socket"""
        if connection_id and connection_id in self.connections:
            self.connections[connection_id]['socket'].sendall(data)
            self.logger.info(f"Server sent {len(data)} bytes to client {connection_id}")
        else:
            self.socket.sendall(data)
            self.logger.info(f"Client sent {len(data)} bytes")

    def receive(self, expected_length=None, connection_id: Optional[int] = None) -> bytes:
        """Receive data from specific client or through client socket"""
        data = b""
        receive_socket = (self.connections[connection_id]['socket'] 
                         if connection_id in self.connections 
                         else self.socket)

        while expected_length is None or len(data) < expected_length:
            chunk = receive_socket.recv(4096 if expected_length is None 
                                      else expected_length - len(data))
            if not chunk:
                break
            data += chunk

        self.logger.info(f"Received {len(data)} bytes")
        return data

    def close_connection(self, connection_id: int):
        """Close a specific client connection"""
        if connection_id in self.connections:
            try:
                self.connections[connection_id]['socket'].shutdown(socket.SHUT_RDWR)
                self.connections[connection_id]['socket'].close()
                del self.connections[connection_id]
                self.logger.info(f"Closed connection {connection_id}")
            except OSError as e:
                self.logger.warning(f"Error closing connection {connection_id}: {e}")
            
    def close(self):
        """Close all connections and server socket"""
        # Close all client connections
        for connection_id in list(self.connections.keys()):
            self.close_connection(connection_id)
            
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()
            self.logger.info("Server socket closed")
        except OSError as e:
            self.logger.warning(f"Error during socket shutdown: {e}")
