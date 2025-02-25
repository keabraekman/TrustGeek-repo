# import ssl
# import socket
# import datetime
# import requests
# from urllib.parse import urlparse
# import pandas as pd
# from cryptography import x509
# from OpenSSL import SSL
# import socket
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
# from cryptography.x509.ocsp import OCSPRequestBuilder
# from cryptography.hazmat.primitives import serialization

# from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
# from cryptography.hazmat.backends import default_backend
# from cryptography.x509.ocsp import (
#     OCSPRequestBuilder,
#     load_der_ocsp_response,
#     OCSPResponseStatus,
#     OCSPCertStatus
# )
# from cryptography.hazmat.primitives import serialization


# def create_secure_connection(host, port=443, timeout=5):
#     print('checking ' + host)
#     context = ssl.create_default_context()
#     context.check_hostname = True
#     sock = socket.create_connection((host, port), timeout=timeout)
#     ssock = context.wrap_socket(sock, server_hostname=host)
#     return ssock

# def check_protocol(ssock):
#     """
#     Check the TLS protocol version and cipher strength.
#     """
#     errors = []
#     protocol = ssock.version()
#     cipher_info = ssock.cipher()
#     cipher_name = cipher_info[0] if cipher_info else ""
    
#     if protocol in ("TLSv1", "TLSv1.1"):
#         errors.append(f"Outdated TLS protocol used ({protocol})")
    
#     weak_ciphers = ['RC4', 'DES', '3DES']
#     if any(weak in cipher_name.upper() for weak in weak_ciphers):
#         errors.append(f"Weak cipher suite used ({cipher_name})")
    
#     forward_secrecy_ciphers = ["DHE", "ECDHE", "TLS_AES_", "TLS_CHACHA20_POLY1305_SHA256"]
#     if not any(kw in cipher_name.upper() for kw in forward_secrecy_ciphers):
#         errors.append("Lack of forward secrecy")
    
#     return errors


# def get_certificate_chain(host, port=443):
#     """
#     Retrieve the certificate chain using PyOpenSSL.
#     """
#     ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
#     conn = socket.create_connection((host, port))
#     ssl_conn = SSL.Connection(ctx, conn)
#     ssl_conn.set_tlsext_host_name(host.encode())
#     ssl_conn.set_connect_state()
#     ssl_conn.do_handshake()
#     chain = ssl_conn.get_peer_cert_chain()
#     ssl_conn.close()
#     conn.close()
#     return chain


# def check_certificates(ssock, host, port=443):
#     """
#     Check various aspects of the SSL certificate:
#       - Certificate chain completeness
#       - Validity period
#       - Self-signed status
#       - Subject Alternative Names (SAN)
#       - Signature hash strength
#     """
#     errors = []
    
#     # Check for complete certificate chain
#     try:
#         chain = get_certificate_chain(host, port)
#         if len(chain) < 2:
#             errors.append("Incomplete certificate chain (missing intermediates)")
#     except Exception as e:
#         print("Cannot retrieve certificate chain")
    
#     # Retrieve the certificate (text form)
#     cert = ssock.getpeercert()
    
#     # Validate certificate dates
#     not_before_str = cert.get("notBefore")
#     not_after_str = cert.get("notAfter")
#     date_format = "%b %d %H:%M:%S %Y %Z"
#     try:
#         not_before = datetime.datetime.strptime(not_before_str, date_format)
#         not_after = datetime.datetime.strptime(not_after_str, date_format)
#         now = datetime.datetime.now(datetime.timezone.utc)
#         if now < not_before:
#             errors.append("Certificate not yet valid")
#         if now > not_after:
#             errors.append("Expired certificate")
#     except Exception as e:
#         # print("Date parsing error:", e)
#         print('')
    
#     # Check if certificate is self-signed (subject equals issuer)
#     subject = dict(x[0] for x in cert.get("subject", ()))
#     issuer = dict(x[0] for x in cert.get("issuer", ()))
#     if subject == issuer:
#         errors.append("Self-signed certificate")
    
#     # Check Subject Alternative Name (SAN) for the host
#     san = cert.get("subjectAltName", ())
#     dns_names = [entry[1] for entry in san if entry[0].lower() == "dns"]
#     if dns_names:
#         if host not in dns_names:
#             errors.append("Hostname not found in SAN: " + ", ".join(dns_names))
#     else:
#         errors.append("No SAN entries in certificate")
    
#     # Check the signature algorithm strength using the cryptography module
#     try:
#         der_cert = ssock.getpeercert(binary_form=True)
#         cert_obj = x509.load_der_x509_certificate(der_cert, default_backend())
#         if isinstance(cert_obj.signature_hash_algorithm, (hashes.MD5, hashes.SHA1)):
#             errors.append(f"Weak signature algorithm: {cert_obj.signature_hash_algorithm.name}")
#     except Exception as e:
#         print("Error checking signature algorithm:", e)
    
#     return errors


# def check_security_headers(host):
#     """
#     Check for the presence of security headers such as HSTS.
#     """
#     errors = []
#     try:
#         url = f"https://{host}"
#         response = requests.get(url, timeout=5)
#         if "strict-transport-security" not in response.headers:
#             errors.append("HSTS header missing")
#     except Exception as e:
#         errors.append("HSTS check failed: " + str(e))
#     return errors


# def check_certificate_revocation(host, port=443, timeout=5):
#     """
#     Check the certificate revocation status using OCSP.
#     Only adds an error if the certificate is explicitly revoked.
#     If the revocation status cannot be determined (e.g. OCSP URL is missing or request fails),
#     no error is returned.
#     """
#     print("Starting certificate revocation check...")
#     errors = []
#     try:
#         # Establish a secure connection to obtain the leaf certificate.
#         ssock = create_secure_connection(host, port, timeout)
#         leaf_der = ssock.getpeercert(binary_form=True)
#         leaf_cert = x509.load_der_x509_certificate(leaf_der, default_backend())

#         # Retrieve the certificate chain to extract the issuer certificate.
#         chain = get_certificate_chain(host, port)
#         if len(chain) < 2:
#             print("Incomplete certificate chain; skipping OCSP check.")
#             return []
#         issuer_cert = chain[1].to_cryptography()

#         # Try to extract the OCSP URL from the Authority Information Access (AIA) extension.
#         try:
#             aia_ext = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
#         except x509.ExtensionNotFound:
#             print("AIA extension not found; skipping OCSP check.")
#             return []

#         aia = aia_ext.value
#         # Safely extract OCSP URLs from the AIA extension.
#         ocsp_urls = [
#             desc.access_location.value if hasattr(desc.access_location, "value") else str(desc.access_location)
#             for desc in aia
#             if desc.access_method == AuthorityInformationAccessOID.OCSP
#         ]
#         if not ocsp_urls:
#             print("No OCSP URL found in AIA extension; skipping OCSP check.")
#             return []
#         ocsp_url = ocsp_urls[0]

#         # Build the OCSP request for the leaf certificate.
#         builder = OCSPRequestBuilder()
#         builder = builder.add_certificate(leaf_cert, issuer_cert, leaf_cert.signature_hash_algorithm)
#         ocsp_request = builder.build()
#         req_data = ocsp_request.public_bytes(encoding=serialization.Encoding.DER)

#         # Send the OCSP request via HTTP POST.
#         headers = {'Content-Type': 'application/ocsp-request'}
#         ocsp_response = requests.post(ocsp_url, data=req_data, headers=headers, timeout=timeout)
#         if ocsp_response.status_code != 200:
#             print(f"OCSP responder returned status {ocsp_response.status_code}; skipping revocation check.")
#             return []

#         # Parse the OCSP response.
#         ocsp_resp = load_der_ocsp_response(ocsp_response.content)
#         if ocsp_resp.response_status == OCSPResponseStatus.SUCCESSFUL:
#             if ocsp_resp.certificate_status == OCSPCertStatus.REVOKED:
#                 errors.append("Certificate has been revoked")
#     except Exception as e:
#         # If any error occurs during the OCSP process, we consider the revocation status as unknown.
#         print("Exception during OCSP check:", e)
#         return []
    
#     print("OCSP check completed.")
#     return errors

# def security_errors(host, port=443):
#     """
#     Aggregate all SSL/TLS related errors for the given host.
#     """
#     errors = []
#     try:
#         ssock = create_secure_connection(host, port)
#         errors += check_protocol(ssock)
#         errors += check_certificates(ssock, host, port)
#         errors += check_security_headers(host)
#         errors += check_certificate_revocation(host)
#         ssock.close()
#     except Exception as e:
#         errors.append(str(e))
#     print('Errors = ', errors)
#     if not errors:
#         return None
#     print('cert revocation done')
#     return errors


# def website_vulnerabilities_output(df):
#     """
#     Processes the DataFrame by checking the SSL certificate for each website.
#     Parameters:
#         df (pd.DataFrame): DataFrame containing at least columns 'Company Website Full' (websites).
#     Returns:
#         pd.DataFrame: The updated DataFrame with a new column 'vulnerabilities'
#     """
#     # Apply the check_ssl_certificate function on each website in column 'P'
#     # df['https_diagnostic'] = df['Company Website Full'].apply(lambda website: check_ssl_certificate(website, port=443) if pd.notnull(website) else None)
#     # df['AM'] = df['P'].apply(lambda website: check_ssl_certificate(website, port=443) if pd.notnull(website) else None)
#     df['website_vulnerabilities'] = df['Company Website Full'].apply(
#         lambda website: security_errors(website, port=443) if pd.notnull(website) else None
#     )
#     return df


# if __name__ == "__main__":
#     # For testing: prompt the user for a website and print the diagnostics.
#     website = 'www.plexicus.com'
#     # errs = security_errors(website)
#     errs = check_certificate_revocation(website)
#     if errs:
#         print("Errors detected:", "; ".join(errs))
#     else:
#         print("No errors detected.")





#!/usr/bin/env python3
import ssl
import socket
import datetime
import requests
import time
import json
import pandas as pd
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509.ocsp import (
    OCSPRequestBuilder,
    load_der_ocsp_response,
    OCSPResponseStatus,
    OCSPCertStatus
)

# Optional: for OWASP ZAP integration
try:
    from zapv2 import ZAPv2
except ImportError:
    ZAPv2 = None

def create_secure_connection(host, port=443, timeout=5):
    """Establish a secure TLS connection to the host."""
    print(f"Establishing secure connection to {host}:{port}")
    context = ssl.create_default_context()
    context.check_hostname = True
    sock = socket.create_connection((host, port), timeout=timeout)
    ssock = context.wrap_socket(sock, server_hostname=host)
    return ssock

def check_tls_configuration(ssock):
    """Check TLS protocol version and cipher suite strength."""
    errors = []
    protocol = ssock.version()
    cipher_info = ssock.cipher()
    cipher_name = cipher_info[0] if cipher_info else ""
    print(f"TLS Protocol: {protocol}, Cipher: {cipher_name}")

    if protocol in ("TLSv1", "TLSv1.1"):
        errors.append(f"Outdated TLS protocol used: {protocol}")

    weak_ciphers = ['RC4', 'DES', '3DES']
    if any(weak in cipher_name.upper() for weak in weak_ciphers):
        errors.append(f"Weak cipher suite used: {cipher_name}")

    forward_secrecy_keywords = ["DHE", "ECDHE", "TLS_AES_", "TLS_CHACHA20_POLY1305_SHA256"]
    if not any(kw in cipher_name.upper() for kw in forward_secrecy_keywords):
        errors.append("Lack of forward secrecy in cipher suite")
    return errors

def get_certificate_chain(host, port=443):
    """Retrieve the certificate chain using PyOpenSSL."""
    from OpenSSL import SSL
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

def check_certificate_details(ssock, host, port=443):
    """Check certificate chain, validity period, SAN, self-signed status, and signature algorithm."""
    errors = []

    # Check for a complete certificate chain
    try:
        chain = get_certificate_chain(host, port)
        if len(chain) < 2:
            errors.append("Incomplete certificate chain (missing intermediates)")
    except Exception as e:
        errors.append("Certificate chain retrieval error: " + str(e))

    cert = ssock.getpeercert()

    # Validity period check
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
        # Instead of adding a date parsing error, just ignore it
        # errors.append(f"Date parsing error: {e}")
        pass

    # Check if certificate is self-signed (subject equals issuer)
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    if subject == issuer:
        errors.append("Self-signed certificate detected")

    # Check Subject Alternative Names (SAN)
    san = cert.get("subjectAltName", ())
    dns_names = [entry[1] for entry in san if entry[0].lower() == "dns"]
    if dns_names:
        if host not in dns_names and not any(host in name for name in dns_names):
            errors.append("Hostname not found in certificate SAN: " + ", ".join(dns_names))
    else:
        errors.append("No Subject Alternative Names (SAN) found in certificate")

    # Check signature algorithm strength
    try:
        der_cert = ssock.getpeercert(binary_form=True)
        cert_obj = x509.load_der_x509_certificate(der_cert, default_backend())
        sig_algo = cert_obj.signature_hash_algorithm.name
        if sig_algo.lower() in ("md5", "sha1"):
            errors.append(f"Weak signature algorithm used: {sig_algo}")
    except Exception as e:
        errors.append("Error checking signature algorithm: " + str(e))
    return errors

def check_ocsp_revocation(host, port=443, timeout=5):
    """Check the certificate revocation status using OCSP."""
    print("Starting OCSP revocation check...")
    errors = []
    try:
        ssock = create_secure_connection(host, port, timeout)
        leaf_der = ssock.getpeercert(binary_form=True)
        leaf_cert = x509.load_der_x509_certificate(leaf_der, default_backend())
        chain = get_certificate_chain(host, port)
        if len(chain) < 2:
            print("Incomplete certificate chain; skipping OCSP check.")
            return errors
        issuer_cert = chain[1].to_cryptography()

        try:
            aia_ext = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        except x509.ExtensionNotFound:
            print("AIA extension not found; skipping OCSP check.")
            return errors

        aia = aia_ext.value
        ocsp_urls = [
            desc.access_location.value if hasattr(desc.access_location, "value") else str(desc.access_location)
            for desc in aia
            if desc.access_method == AuthorityInformationAccessOID.OCSP
        ]
        if not ocsp_urls:
            print("No OCSP URL found; skipping OCSP check.")
            return errors
        ocsp_url = ocsp_urls[0]

        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(leaf_cert, issuer_cert, leaf_cert.signature_hash_algorithm)
        ocsp_request = builder.build()
        req_data = ocsp_request.public_bytes(encoding=serialization.Encoding.DER)

        headers = {'Content-Type': 'application/ocsp-request'}
        ocsp_response = requests.post(ocsp_url, data=req_data, headers=headers, timeout=timeout)
        if ocsp_response.status_code != 200:
            print(f"OCSP responder returned status {ocsp_response.status_code}; skipping check.")
            return errors

        ocsp_resp = load_der_ocsp_response(ocsp_response.content)
        if ocsp_resp.response_status == OCSPResponseStatus.SUCCESSFUL:
            if ocsp_resp.certificate_status == OCSPCertStatus.REVOKED:
                errors.append("Certificate has been revoked (OCSP)")
        else:
            print("OCSP response not successful.")
    except Exception as e:
        print("OCSP check error:", e)
    finally:
        try:
            ssock.close()
        except Exception:
            pass
    print("OCSP check completed.")
    return errors

def check_security_headers(host):
    """Check for common HTTP security headers."""
    errors = []
    url = f"https://{host}"
    try:
        response = requests.get(url, timeout=5)
        headers = {k.lower(): v for k, v in response.headers.items()}

        if "strict-transport-security" not in headers:
            errors.append("HSTS header missing")
        if "content-security-policy" not in headers:
            errors.append("Content-Security-Policy header missing")
        if "x-content-type-options" not in headers:
            errors.append("X-Content-Type-Options header missing")
        if "x-frame-options" not in headers:
            errors.append("X-Frame-Options header missing")
        if "referrer-policy" not in headers:
            errors.append("Referrer-Policy header missing")
        if "x-xss-protection" not in headers:
            errors.append("X-XSS-Protection header missing")
    except Exception as e:
        errors.append("Failed to retrieve security headers: " + str(e))
    return errors

def check_cookie_security(host):
    """Check if cookies are set with Secure and HttpOnly flags."""
    errors = []
    url = f"https://{host}"
    try:
        response = requests.get(url, timeout=5)
        if 'set-cookie' in response.headers:
            cookies = response.headers.get('set-cookie')
            if "secure" not in cookies.lower():
                errors.append("Cookie missing 'Secure' flag")
            if "httponly" not in cookies.lower():
                errors.append("Cookie missing 'HttpOnly' flag")
    except Exception as e:
        errors.append("Failed to check cookie security: " + str(e))
    return errors

def zap_scan(host, zap_api_key=None, zap_address='127.0.0.1', zap_port='8080'):
    """
    Optional integration with OWASP ZAP for an active scan.
    Requires:
      - OWASP ZAP to be running (in daemon mode)
      - python-owasp-zap-v2.4 installed
    """
    if ZAPv2 is None:
        return ["OWASP ZAP integration not available (python-owasp-zap-v2.4 not installed)"]

    errors = []
    target = f"https://{host}"
    zap = ZAPv2(apikey=zap_api_key, proxies={
        'http': f'http://{zap_address}:{zap_port}',
        'https': f'http://{zap_address}:{zap_port}'
    })

    print("Starting OWASP ZAP scan...")
    try:
        zap.urlopen(target)
        time.sleep(2)
        # Start spidering the target
        spider_id = zap.spider.scan(target)
        time.sleep(2)
        while int(zap.spider.status(spider_id)) < 100:
            print("Spider progress: " + zap.spider.status(spider_id) + "%")
            time.sleep(2)
        print("Spider completed.")

        # Start active scan
        ascan_id = zap.ascan.scan(target)
        while int(zap.ascan.status(ascan_id)) < 100:
            print("Active scan progress: " + zap.ascan.status(ascan_id) + "%")
            time.sleep(5)
        print("Active scan completed.")

        alerts = zap.core.alerts(baseurl=target)
        if alerts:
            errors.append(f"OWASP ZAP found {len(alerts)} potential vulnerabilities.")
        else:
            print("No vulnerabilities found by OWASP ZAP.")
    except Exception as e:
        errors.append("OWASP ZAP scan error: " + str(e))
    return errors

def comprehensive_security_scan(host, port=443, use_zap=False, zap_api_key=None):
    """
    Aggregate all security checks for the given host.
    Returns a dictionary of issues found.
    """
    scan_results = {}

    # TLS/SSL and certificate checks
    try:
        ssock = create_secure_connection(host, port)
    except Exception as e:
        scan_results["connection_error"] = f"Failed to establish connection: {e}"
        return scan_results

    scan_results["tls_errors"] = check_tls_configuration(ssock)
    scan_results["certificate_errors"] = check_certificate_details(ssock, host, port)
    scan_results["ocsp_errors"] = check_ocsp_revocation(host, port)
    try:
        ssock.close()
    except Exception:
        pass

    # HTTP security headers
    scan_results["header_errors"] = check_security_headers(host)
    # Cookie security check
    scan_results["cookie_errors"] = check_cookie_security(host)

    # Optional OWASP ZAP scan
    if use_zap:
        scan_results["zap_errors"] = zap_scan(host, zap_api_key=zap_api_key)

    # -------------------------------------------------------------------------
    # Remove any date parsing errors (already not added) and remove empty lists
    # -------------------------------------------------------------------------

    # 1) Remove any empty lists from the final dictionary
    #    (e.g., if tls_errors == [], remove that key entirely).
    keys_to_delete = []
    for key, value in scan_results.items():
        # Only remove if it's a list and is empty
        if isinstance(value, list) and len(value) == 0:
            keys_to_delete.append(key)

    for key in keys_to_delete:
        del scan_results[key]

    return scan_results

def process_websites_from_csv(input_csv, output_csv, url_column='Company Website Full', use_zap=False, zap_api_key=None):
    """
    Process a CSV of websites and add a new column with vulnerability findings.
    """
    df = pd.read_csv(input_csv)
    vulnerabilities = []
    for index, row in df.iterrows():
        website = row[url_column]
        if pd.notnull(website):
            parsed = urlparse(website)
            hostname = parsed.netloc if parsed.netloc else parsed.path
            print(f"\nScanning {hostname}...")
            results = comprehensive_security_scan(hostname, use_zap=use_zap, zap_api_key=zap_api_key)
            vulnerabilities.append(results)
        else:
            vulnerabilities.append(None)
    df['vulnerabilities'] = vulnerabilities
    df.to_csv(output_csv, index=False)
    print(f"Results saved to {output_csv}")

def website_vulnerabilities_output(df, use_zap=False, zap_api_key=None):
    """
    Processes the DataFrame by checking the security vulnerabilities for each website.
    Prints the percentage progress as it processes the file.
    
    Parameters:
        df (pd.DataFrame): DataFrame containing at least a 'Company Website Full' column.
        use_zap (bool): Whether to include the OWASP ZAP scan.
        zap_api_key (str): API key for OWASP ZAP, if used.
    
    Returns:
        pd.DataFrame: The updated DataFrame with a new column 'website_vulnerabilities'
                      containing the scan results (non-empty findings only).
    """
    total = len(df)
    vulnerabilities = []    
    for i, website in enumerate(df['Company Website Full']):
        if pd.notnull(website):
            result = comprehensive_security_scan(website, use_zap=use_zap, zap_api_key=zap_api_key)
        else:
            result = None
        vulnerabilities.append(result)
        
        # Calculate and print progress percentage
        progress = ((i + 1) / total) * 100
        print(f"Progress: {progress:.2f}%")
    
    # Ensure the final progress is printed on a new line
    print()
    
    df['website_vulnerabilities'] = vulnerabilities
    return df


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Comprehensive Website Security Scanner")
    parser.add_argument("url", nargs="?", help="URL of the website to scan (e.g., www.example.com)")
    parser.add_argument("--zap", action="store_true", help="Include OWASP ZAP scan (requires ZAP and python-owasp-zap-v2.4)")
    parser.add_argument("--zap_api_key", type=str, default=None, help="API key for OWASP ZAP")
    parser.add_argument("--csv", type=str, help="Input CSV file containing websites")
    parser.add_argument("--output_csv", type=str, default="vulnerabilities_output.csv", help="Output CSV file for vulnerabilities")
    args = parser.parse_args()

    if args.csv:
        process_websites_from_csv(args.csv, args.output_csv, use_zap=args.zap, zap_api_key=args.zap_api_key)
    elif args.url:
        hostname = args.url
        parsed = urlparse(hostname)
        hostname = parsed.netloc if parsed.netloc else parsed.path
        results = comprehensive_security_scan(hostname, use_zap=args.zap, zap_api_key=args.zap_api_key)
        # Print the final results (with empty lists removed)
        print(json.dumps(results, indent=2))
    else:
        print("Please provide a URL or CSV file containing websites to scan.")
