from projectclasses.tcp import TCP
from projectclasses.tls import TLS

class Client:
    def __init__(self, host, port):
        self.tcp = TCP(host, port)
        self.tls = None

    def connect(self):
        # Step 1: Establish TCP connection
        self.tcp.connect()

        # Step 2: Initialize TLS instance
        self.tls = TLS(self.tcp)

        # Step 3: Perform TLS handshake
        # self.tls.send_tls_record(22, (3, 3), b"ClientHello")
        # _, _, response = self.tls.receive_tls_record()
        # if response != b"ServerHello":
        #     raise ConnectionError("TLS handshake failed")

    def send(self, data):
        self.tls.send_tls_record(23, (3, 3), data)

    def receive(self):
        _, _, data = self.tls.receive_tls_record()
        return data

    def close(self):
        self.tcp.close()
