# SSL MCP Server

![Test Status](https://github.com/GitHub30/ssl-mcp-server/actions/workflows/test.yml/badge.svg)

A FastMCP server for SSL certificate operations, built with `fastmcp`, `pyopenssl`, and `cryptography`.

## MCP Server URL

```
https://sslmcp.fastmcp.app/mcp
```

## Features

This MCP server provides the following tools:

- **`get_certificate_and_chain`**: Retrieves the SSL certificate and its full chain from a remote server.
- **`generate_self_signed_cert`**: Generates a self-signed SSL certificate for development purposes.
- **`parse_certificate_pem`**: Parses a PEM-encoded certificate string to extract details.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/GitHub30/ssl-mcp-server.git
   cd ssl-mcp-server
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the server using `fastmcp`:

```bash
fastmcp run server.py
```

## Development

Run tests:

```bash
python test.py
```
