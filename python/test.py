import threading
import logging
import time
from projectclasses.server import Server
from projectclasses.client import Client

def setup_logging():
    """Configure logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger('TestMain')

def run_client(name: str, cipher_suite: str):
    """Run a client with specified cipher suite"""
    logger = logging.getLogger(f'Client_{name}')
    try:
        # Create and connect client
        client = Client('localhost', 8444, [cipher_suite])
        client.connect()
        
        # Send test message
        message = f"Hello from {name} using {cipher_suite}!"
        client.send(message)
        logger.info(f"Sent: {message}")
        
        # Receive response
        response = client.receive()
        logger.info(f"Received: {response.decode('utf-8')}")
        
        # Keep connection alive
        while True:
            time.sleep(1)
            client.send(f"Heartbeat from {name}")
            response = client.receive()
            logger.debug(f"Heartbeat response: {response.decode('utf-8')}")
            
    except Exception as e:
        logger.error(f"Client error: {e}")

def main():
    logger = setup_logging()
    logger.info("Starting TLS test with RSA and DHE clients")

    # Start server
    server = Server('localhost', 8444)
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(1)  # Wait for server to start

    try:
        # Start RSA client
        rsa_thread = threading.Thread(
            target=run_client, 
            args=("RSA_Client", Client.RSA_SUITE)
        )
        rsa_thread.daemon = True
        rsa_thread.start()
        logger.info("Started RSA client")

        time.sleep(2)  # Wait between clients

        # Start DHE client
        dhe_thread = threading.Thread(
            target=run_client, 
            args=("DHE_Client", Client.DHE_SUITE)
        )
        dhe_thread.daemon = True
        dhe_thread.start()
        logger.info("Started DHE client")

        # Keep main thread running
        while True:
            time.sleep(1)
            if not rsa_thread.is_alive() and not dhe_thread.is_alive():
                logger.error("Both clients have died")
                break
                
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        server.stop()
        logger.info("Server stopped")

if __name__ == "__main__":
    main()