#!/usr/bin/env python3
import ssl
import socket
import OpenSSL
from datetime import datetime
from OpenSSL import crypto

def get_cert_chain(hostname, port=443):
    """Get the certificate chain for a given hostname."""
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect to the server
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert(binary_form=True), ssock.getpeercert(chain=True)
    except Exception as e:
        print(f"Error getting certificate: {e}")
        return None, None

def parse_cert(cert_data):
    """Parse certificate data and return formatted information."""
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)
        
        # Get certificate information
        subject = dict(cert.get_subject().get_components())
        issuer = dict(cert.get_issuer().get_components())
        
        # Format dates
        not_before = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
        not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        
        # Get fingerprint
        fingerprint = cert.digest('sha256').decode('ascii')
        
        return {
            'subject': subject,
            'issuer': issuer,
            'not_before': not_before,
            'not_after': not_after,
            'fingerprint': fingerprint
        }
    except Exception as e:
        print(f"Error parsing certificate: {e}")
        return None

def format_dn(dn_dict):
    """Format Distinguished Name components."""
    components = []
    for key, value in dn_dict.items():
        if key in [b'CN', b'O', b'L', b'ST', b'C']:
            components.append(f"{key.decode('utf-8')}={value.decode('utf-8')}")
    return ", ".join(components)

def display_cert_info(cert_info, index):
    """Display certificate information in a formatted way."""
    print(f"\nCertificate {index}")
    print("┌" + "─" * 75)
    print(f"│ 类型: 服务器证书")
    print(f"│ 主体: {format_dn(cert_info['subject'])}")
    print(f"│ 颁发者: {format_dn(cert_info['issuer'])}")
    print(f"│ 有效期: {cert_info['not_before'].strftime('%Y-%m-%d %H:%M:%S')} 至 {cert_info['not_after'].strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"│ 指纹(SHA-256): {cert_info['fingerprint']}")
    print("└" + "─" * 75)

def display_connection_info(hostname, port, protocol, cipher):
    """Display connection information."""
    print("\nSSL/TLS Connection Test Results")
    print("═" * 75)
    print("\nBasic Information")
    print("─" * 75)
    print(f"Host: {hostname}")
    print(f"Port: {port}")
    print("\nProtocol Information")
    print("─" * 75)
    print(f"Protocol: {protocol}")
    print(f"Cipher Suite: {cipher}")
    print("\nCertificate Chain")
    print("─" * 75)

def main():
    hostname = "github.com"
    port = 443
    
    cert_data, cert_chain = get_cert_chain(hostname, port)
    
    if cert_data:
        # Get connection info
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                protocol = ssock.version()
                cipher = ssock.cipher()[0]
        
        display_connection_info(hostname, port, protocol, cipher)
        
        # Display end-entity certificate
        cert_info = parse_cert(cert_data)
        if cert_info:
            display_cert_info(cert_info, 1)
        
        # Display intermediate certificates if available
        if cert_chain:
            for i, cert in enumerate(cert_chain, 2):
                cert_info = parse_cert(cert)
                if cert_info:
                    display_cert_info(cert_info, i)
    else:
        print("Failed to get certificate information")

if __name__ == "__main__":
    main() 