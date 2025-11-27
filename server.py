from fastmcp import FastMCP
import ssl
import socket
import OpenSSL
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID

# Initialize FastMCP server
mcp = FastMCP("ssl-mcp-server")

def _parse_x509_certificate(cert: x509.Certificate) -> Dict[str, Any]:
    """Helper to parse a cryptography X509 certificate into a dictionary."""
    
    def _get_name_attribute(name: x509.Name, oid: NameOID) -> Optional[str]:
        try:
            attributes = name.get_attributes_for_oid(oid)
            if attributes:
                return attributes[0].value
        except Exception:
            pass
        return None

    subject = cert.subject
    issuer = cert.issuer
    
    # Extract Subject Alternative Names
    sans = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    return {
        "subject": {
            "CN": _get_name_attribute(subject, NameOID.COMMON_NAME),
            "O": _get_name_attribute(subject, NameOID.ORGANIZATION_NAME),
            "OU": _get_name_attribute(subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
            "L": _get_name_attribute(subject, NameOID.LOCALITY_NAME),
            "ST": _get_name_attribute(subject, NameOID.STATE_OR_PROVINCE_NAME),
            "C": _get_name_attribute(subject, NameOID.COUNTRY_NAME),
        },
        "issuer": {
            "CN": _get_name_attribute(issuer, NameOID.COMMON_NAME),
            "O": _get_name_attribute(issuer, NameOID.ORGANIZATION_NAME),
            "OU": _get_name_attribute(issuer, NameOID.ORGANIZATIONAL_UNIT_NAME),
            "L": _get_name_attribute(issuer, NameOID.LOCALITY_NAME),
            "ST": _get_name_attribute(issuer, NameOID.STATE_OR_PROVINCE_NAME),
            "C": _get_name_attribute(issuer, NameOID.COUNTRY_NAME),
        },
        "serial_number": cert.serial_number,
        "version": cert.version.name,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "has_expired": datetime.now(timezone.utc) > cert.not_valid_after_utc,
        "subject_alt_names": sans,
        "signature_algorithm": cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid),
    }



@mcp.tool(annotations={"readOnlyHint": True})
def get_certificate_and_chain(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Retrieves the SSL certificate and its chain from a remote server.
    
    Args:
        hostname: The hostname to connect to.
        port: The port to connect to (default: 443).
    """
    try:
        # Use OpenSSL directly to reliably get the chain
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        conn = OpenSSL.SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        conn.connect((hostname, port))
        conn.set_tlsext_host_name(hostname.encode('utf-8'))
        conn.set_connect_state()
        conn.do_handshake()
        
        chain = conn.get_peer_cert_chain()
        if not chain:
            return {"error": "No certificate chain found"}
            
        # Convert OpenSSL certs to cryptography certs
        chain_details = [_parse_x509_certificate(c.to_cryptography()) for c in chain]
        
        conn.close()
        
        return {
            "certificate": chain_details[0],
            "chain": chain_details[1:] # The rest are the chain
        }

    except Exception as e:
        return {"error": str(e)}

@mcp.tool(annotations={"readOnlyHint": True})
def generate_self_signed_cert(common_name: str, valid_days: int = 365) -> Dict[str, str]:
    """
    Generates a self-signed SSL certificate.
    
    Args:
        common_name: The Common Name (CN) for the certificate (e.g., "localhost").
        valid_days: Number of days the certificate is valid.
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Organization"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Organizational Unit"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=valid_days)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    ).sign(key, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    return {
        "certificate_pem": cert_pem,
        "private_key_pem": key_pem
    }

@mcp.tool(annotations={"readOnlyHint": True})
def parse_certificate_pem(pem_content: str) -> Dict[str, Any]:
    """
    Parses a PEM-encoded certificate and returns its details.
    
    Args:
        pem_content: The PEM encoded certificate string.
    """
    try:
        cert = x509.load_pem_x509_certificate(pem_content.encode('utf-8'))
        return _parse_x509_certificate(cert)
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    mcp.run()
