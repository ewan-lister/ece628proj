# server1.py

from projectclasses.tcp import TCP  # Import the TCP class
from projectclasses.server import Server
import time

if __name__ == "__main__":
    server = Server('127.0.0.1', 65432)  # Create an instance of Server
    server.start()  # Start the server

    # Simulate server communication
    time.sleep(2)  # Wait for the client to connect and send a message
    message = server.receive()  # Receive a message from the client
    # print(f"Server received: {message}")
    
    # Send a response
    server.send("Hello from server!")
    # print("Server sent: 'Hello from server!'")
    
    # Close the connection
    server.close()
