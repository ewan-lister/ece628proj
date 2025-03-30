# server1.py

from projectclasses.tcp import TCP  # Import the TCP class
from projectclasses.server import Server
import time
import signal
import sys
import logging

def setup_logging():
    """Configure logging for the server"""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\nShutting down server...")
    if 'server' in globals():
        server.close()
    sys.exit(0)

if __name__ == "__main__":
    # Set up logging
    setup_logging()
    logger = logging.getLogger('ServerMain')

    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    # Create and start server
    server = Server("localhost", 8443, ["TLS_RSA_WITH_AES_256_CBC_SHA256","TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"])
    try:
        logger.info("Starting server on localhost:8443")
        server.start()  # This will run indefinitely, accepting clients
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        server.close()
