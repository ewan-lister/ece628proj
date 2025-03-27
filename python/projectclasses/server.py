from projectclasses.tcp import TCP
from projectclasses.tls import TLS

class Server:
    def __init__(self, host, port):
        self.tcp = TCP(host, port)
        self.tls = None

    def start(self):
        # Step 1: Establish TCP connection
        self.tcp.connect(is_server=True)

        # Step 2: Initialize TLS instance
        self.tls = TLS(self.tcp)

        self.accept()

    def accept(self):
        
    def send(self, data):
        self.tls.send_tls_record(23, (3, 3), data)

    def receive(self):
        _, _, data = self.tls.receive_tls_record()
        return data

    def close(self):
        self.tcp.close()
