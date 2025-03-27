# client.py

from projectclasses.tcp import TCP
from projectclasses.client import Client
import time


if __name__ == "__main__":
    client = Client('127.0.0.1', 65432)  # Create an instance of Client
    client.connect()
    
    # Simulate client sending a message
    time.sleep(1)  # Wait a moment for server to be ready
    client.send("Hello from client!")
    # print("Client sent: 'Hello from client!'")

    # Receive a response from the server
    message = client.receive()
    # print(f"Client received: {message}")
    
    # Close the connection
    #client.close_connection()
