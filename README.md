# TLS Implementation Project

A Python implementation of TLS 1.2 with support for RSA and DHE key exchange.

## Installation

1. cd into the `python` file

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Linux/Mac
# or
venv\Scripts\activate  # On Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Project (please contact me elister@uwaterloo.ca if you have any issues)

1. Start the server:
```bash
python server1.py
```

2. In another terminal, run the client:
```bash
python client1.py  # For RSA
# or
python client2.py  # For DHE
```

3. Run benchmarks if you want:
```bash
python benchmark_tls.py
```

## Requirements

- Python 3.8 or higher
- cryptography
- pandas
- matplotlib
- openpyxl

## Development

To install in development mode:
```bash
pip install -e .
```
