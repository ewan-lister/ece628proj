import socket
import logging

class TCP:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Logger setup
        self.logger = logging.getLogger('TCP')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def connect(self, is_server=False):
        if is_server:
            self.socket.bind((self.host, self.port))
            self.socket.listen(1)
            self.logger.info(f"Server listening on {self.host}:{self.port}")
            self.connection, self.address = self.socket.accept()
            self.logger.info(f"Connection established with {self.address}")
        else:
            self.socket.connect((self.host, self.port))
            self.logger.info(f"Client connected to {self.host}:{self.port}")

    def send(self, data: bytes):
        if hasattr(self, 'connection'):
            self.connection.sendall(data)
            self.logger.info(f"Server sent {len(data)} bytes")
        else:
            self.socket.sendall(data)
            self.logger.info(f"Client sent {len(data)} bytes")

    def receive(self, expected_length=None) -> bytes:
        data = b""
        receive_socket = self.connection if hasattr(self, 'connection') else self.socket

        # Read in chunks until expected_length is reached
        while expected_length is None or len(data) < expected_length:
            chunk = receive_socket.recv(4096 if expected_length is None else expected_length - len(data))
            if not chunk:
                break  # Connection closed
            data += chunk

        self.logger.info(f"Received {len(data)} bytes")
        return data

    def close(self):
        try:
            if hasattr(self, 'connection'):
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                self.logger.info("Server gracefully closed the connection")
            else:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
                self.logger.info("Client gracefully closed the socket")
        except OSError as e:
            self.logger.warning(f"Error during socket shutdown: {e}")
