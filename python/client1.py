# client.py

from projectclasses.tcp import TCP
from projectclasses.client import Client
import logging
import sys
import time

def setup_logging():
    """Configure logging for the client"""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

if __name__ == "__main__":
    # Set up logging
    setup_logging()
    logger = logging.getLogger('ClientMain')

    try:
        # Create client instance with correct port
        client = Client('localhost', 8444, ["TLS_RSA_WITH_AES_256_CBC_SHA256"])
        logger.info("Connecting to server...")
        client.connect()
        
        #Simulate client sending a message
        time.sleep(1)  # Wait a moment for handshake to complete
        client.send("Hello from client!")
        logger.info("Sent: 'Hello from client!'")

        # Receive response from server
        message = client.receive()
        logger.info(f"Received: {message}")
        
    except ConnectionRefusedError:
        logger.error("Connection refused. Make sure server is running on port 8443")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    finally:
        #client.close()
        pass
