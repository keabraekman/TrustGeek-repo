import ssl
import socket
import datetime
import requests
from urllib.parse import urlparse
import pandas as pd
from cryptography import x509
from OpenSSL import SSL
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509.ocsp import OCSPRequestBuilder
from cryptography.hazmat.primitives import serialization

from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.hazmat.backends import default_backend
from cryptography.x509.ocsp import (
    OCSPRequestBuilder,
    load_der_ocsp_response,
    OCSPResponseStatus,
    OCSPCertStatus
)
from cryptography.hazmat.primitives import serialization


def create_secure_connection(host, port=443, timeout=5):
    print('checking ' + host)
    context = ssl.create_default_context()
    context.check_hostname = True
    sock = socket.create_connection((host, port), timeout=timeout)
    ssock = context.wrap_socket(sock, server_hostname=host)
    return ssock

def check_protocol(ssock):
    """
    Check the TLS protocol version and cipher strength.
    """
    errors = []
    protocol = ssock.version()
    cipher_info = ssock.cipher()
    cipher_name = cipher_info[0] if cipher_info else ""
    
    if protocol in ("TLSv1", "TLSv1.1"):
        errors.append(f"Outdated TLS protocol used ({protocol})")
    
    weak_ciphers = ['RC4', 'DES', '3DES']
    if any(weak in cipher_name.upper() for weak in weak_ciphers):
        errors.append(f"Weak cipher suite used ({cipher_name})")
    
    forward_secrecy_ciphers = ["DHE", "ECDHE", "TLS_AES_", "TLS_CHACHA20_POLY1305_SHA256"]
    if not any(kw in cipher_name.upper() for kw in forward_secrecy_ciphers):
        errors.append("Lack of forward secrecy")
    
    return errors


def get_certificate_chain(host, port=443):
    """
    Retrieve the certificate chain using PyOpenSSL.
    """
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    conn = socket.create_connection((host, port))
    ssl_conn = SSL.Connection(ctx, conn)
    ssl_conn.set_tlsext_host_name(host.encode())
    ssl_conn.set_connect_state()
    ssl_conn.do_handshake()
    chain = ssl_conn.get_peer_cert_chain()
    ssl_conn.close()
    conn.close()
    return chain


def check_certificates(ssock, host, port=443):
    """
    Check various aspects of the SSL certificate:
      - Certificate chain completeness
      - Validity period
      - Self-signed status
      - Subject Alternative Names (SAN)
      - Signature hash strength
    """
    errors = []
    
    # Check for complete certificate chain
    try:
        chain = get_certificate_chain(host, port)
        if len(chain) < 2:
            errors.append("Incomplete certificate chain (missing intermediates)")
    except Exception as e:
        print("Cannot retrieve certificate chain")
    
    # Retrieve the certificate (text form)
    cert = ssock.getpeercert()
    
    # Validate certificate dates
    not_before_str = cert.get("notBefore")
    not_after_str = cert.get("notAfter")
    date_format = "%b %d %H:%M:%S %Y %Z"
    try:
        not_before = datetime.datetime.strptime(not_before_str, date_format)
        not_after = datetime.datetime.strptime(not_after_str, date_format)
        now = datetime.datetime.now(datetime.timezone.utc)
        if now < not_before:
            errors.append("Certificate not yet valid")
        if now > not_after:
            errors.append("Expired certificate")
    except Exception as e:
        # print("Date parsing error:", e)
        print('')
    
    # Check if certificate is self-signed (subject equals issuer)
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    if subject == issuer:
        errors.append("Self-signed certificate")
    
    # Check Subject Alternative Name (SAN) for the host
    san = cert.get("subjectAltName", ())
    dns_names = [entry[1] for entry in san if entry[0].lower() == "dns"]
    if dns_names:
        if host not in dns_names:
            errors.append("Hostname not found in SAN: " + ", ".join(dns_names))
    else:
        errors.append("No SAN entries in certificate")
    
    # Check the signature algorithm strength using the cryptography module
    try:
        der_cert = ssock.getpeercert(binary_form=True)
        cert_obj = x509.load_der_x509_certificate(der_cert, default_backend())
        if isinstance(cert_obj.signature_hash_algorithm, (hashes.MD5, hashes.SHA1)):
            errors.append(f"Weak signature algorithm: {cert_obj.signature_hash_algorithm.name}")
    except Exception as e:
        print("Error checking signature algorithm:", e)
    
    return errors


def check_security_headers(host):
    """
    Check for the presence of security headers such as HSTS.
    """
    errors = []
    try:
        url = f"https://{host}"
        response = requests.get(url, timeout=5)
        if "strict-transport-security" not in response.headers:
            errors.append("HSTS header missing")
    except Exception as e:
        errors.append("HSTS check failed: " + str(e))
    return errors


def check_certificate_revocation(host, port=443, timeout=5):
    """
    Check the certificate revocation status using OCSP.
    Only adds an error if the certificate is explicitly revoked.
    If the revocation status cannot be determined (e.g. OCSP URL is missing or request fails),
    no error is returned.
    """
    print("Starting certificate revocation check...")
    errors = []
    try:
        # Establish a secure connection to obtain the leaf certificate.
        ssock = create_secure_connection(host, port, timeout)
        leaf_der = ssock.getpeercert(binary_form=True)
        leaf_cert = x509.load_der_x509_certificate(leaf_der, default_backend())

        # Retrieve the certificate chain to extract the issuer certificate.
        chain = get_certificate_chain(host, port)
        if len(chain) < 2:
            print("Incomplete certificate chain; skipping OCSP check.")
            return []
        issuer_cert = chain[1].to_cryptography()

        # Try to extract the OCSP URL from the Authority Information Access (AIA) extension.
        try:
            aia_ext = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        except x509.ExtensionNotFound:
            print("AIA extension not found; skipping OCSP check.")
            return []

        aia = aia_ext.value
        # Safely extract OCSP URLs from the AIA extension.
        ocsp_urls = [
            desc.access_location.value if hasattr(desc.access_location, "value") else str(desc.access_location)
            for desc in aia
            if desc.access_method == AuthorityInformationAccessOID.OCSP
        ]
        if not ocsp_urls:
            print("No OCSP URL found in AIA extension; skipping OCSP check.")
            return []
        ocsp_url = ocsp_urls[0]

        # Build the OCSP request for the leaf certificate.
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(leaf_cert, issuer_cert, leaf_cert.signature_hash_algorithm)
        ocsp_request = builder.build()
        req_data = ocsp_request.public_bytes(encoding=serialization.Encoding.DER)

        # Send the OCSP request via HTTP POST.
        headers = {'Content-Type': 'application/ocsp-request'}
        ocsp_response = requests.post(ocsp_url, data=req_data, headers=headers, timeout=timeout)
        if ocsp_response.status_code != 200:
            print(f"OCSP responder returned status {ocsp_response.status_code}; skipping revocation check.")
            return []

        # Parse the OCSP response.
        ocsp_resp = load_der_ocsp_response(ocsp_response.content)
        if ocsp_resp.response_status == OCSPResponseStatus.SUCCESSFUL:
            if ocsp_resp.certificate_status == OCSPCertStatus.REVOKED:
                errors.append("Certificate has been revoked")
    except Exception as e:
        # If any error occurs during the OCSP process, we consider the revocation status as unknown.
        print("Exception during OCSP check:", e)
        return []
    
    print("OCSP check completed.")
    return errors

def security_errors(host, port=443):
    """
    Aggregate all SSL/TLS related errors for the given host.
    """
    errors = []
    try:
        ssock = create_secure_connection(host, port)
        errors += check_protocol(ssock)
        errors += check_certificates(ssock, host, port)
        errors += check_security_headers(host)
        errors += check_certificate_revocation(host)
        ssock.close()
    except Exception as e:
        errors.append(str(e))
    print('Errors = ', errors)
    if not errors:
        return None
    print('cert revocation done')
    return errors


def website_vulnerabilities_output(df):
    """
    Processes the DataFrame by checking the SSL certificate for each website.
    Parameters:
        df (pd.DataFrame): DataFrame containing at least columns 'website_url' (websites).
    Returns:
        pd.DataFrame: The updated DataFrame with a new column 'vulnerabilities'
    """
    # Apply the check_ssl_certificate function on each website in column 'P'
    # df['https_diagnostic'] = df['website_url'].apply(lambda website: check_ssl_certificate(website, port=443) if pd.notnull(website) else None)
    # df['AM'] = df['P'].apply(lambda website: check_ssl_certificate(website, port=443) if pd.notnull(website) else None)
    df['website_vulnerabilities'] = df['website_url'].apply(
        lambda website: security_errors(website, port=443) if pd.notnull(website) else None
    )
    return df


if __name__ == "__main__":
    # For testing: prompt the user for a website and print the diagnostics.
    website = 'www.plexicus.com'
    # errs = security_errors(website)
    errs = check_certificate_revocation(website)
    if errs:
        print("Errors detected:", "; ".join(errs))
    else:
        print("No errors detected.")