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


def get_certificate_chain(host, port=443):
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


def check_ssl_certificate(host, port=443):
    parsed = urlparse(host)
    # If the user provided 'http://www.example.com', parsed.netloc would be 'www.example.com'.
    # If the user provided 'www.example.com' without a scheme, parsed.netloc might be empty,
    # so we use parsed.path instead. This ensures we always get the domain name.
    host = parsed.netloc or parsed.path    
    print('checking : ['+host+']')
    errors = []
    context = ssl.create_default_context()
    context.check_hostname = True  # Will raise error if hostname doesn't match
    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Get protocol version and cipher
                protocol = ssock.version()
                cipher_info = ssock.cipher()  # (cipher_name, ssl_version, secret_bits)
                cipher_name = cipher_info[0] if cipher_info else ""
                # Check protocol version for outdated TLS versions
                if protocol in ("TLSv1", "TLSv1.1"):
                    errors.append("Outdated TLS protocol used (" + protocol + ")")
                # Check for weak ciphers (this is a basic list)
                weak_ciphers = ['RC4', 'DES', '3DES']
                if any(weak in cipher_name.upper() for weak in weak_ciphers):
                    errors.append("Weak cipher suite used (" + cipher_name + ")")
                # Check for forward secrecy (look for ephemeral key exchange methods)
                forward_secrecy_ciphers = ["DHE","ECDHE","TLS_AES_","TLS_CHACHA20_POLY1305_SHA256"]
                if not any(kw in cipher_name.upper() for kw in forward_secrecy_ciphers):
                    errors.append("Lack of forward secrecy")
                # Retrieve certificate details

                # Cryptography strength
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                if isinstance(cert.signature_hash_algorithm, (hashes.MD5, hashes.SHA1)):
                    errors.append(f"Weak signature algorithm: {cert.signature_hash_algorithm.name}")
                
                # Check for certificate chain validation
                # chain = ssock.getpeercertchain()
                # if len(chain) < 2:
                #     errors.append("Incomplete certificate chain (missing intermediates)")
                try:
                    chain = get_certificate_chain(host)
                    if len(chain) < 2:
                        errors.append("Incomplete certificate chain (missing intermediates)")
                except Exception as e:
                    # errors.append("Error retrieving certificate chain: " + str(e))
                    print('Cannot retrieve certificate chain')

                cert = ssock.getpeercert()
    except ssl.CertificateError as ce:
        errors.append("Hostname mismatch: " + str(ce))
        return "; ".join(errors)
    except ssl.SSLError as se:
        errors.append("SSL error: " + str(se))
        return "; ".join(errors)
    except Exception as e:
        print('CONNECTION ERROR')
        errors.append("Connection error: " + str(e))
        return "; ".join(errors)
    # Check certificate validity period
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
        # errors.append("Validity date parsing error: " + str(e))
        print('date error, not appending it')
    # Check if certificate is self-signed (subject equals issuer)
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    if subject == issuer:
        errors.append("Self-signed certificate")
    # Check Subject Alternative Names (SAN) for the host
    san = cert.get("subjectAltName", ())
    dns_names = [entry[1] for entry in san if entry[0].lower() == "dns"]
    if dns_names:
        if host not in dns_names:
            errors.append("Hostname not found in SAN: " + ", ".join(dns_names))
    else:
        errors.append("No SAN entries in certificate")
    # Check for HSTS header using a simple GET request
    try:
        url = f"https://{host}"
        response = requests.get(url, timeout=5)
        if "strict-transport-security" not in response.headers:
            errors.append("HSTS header missing")
    except Exception as e:
        errors.append("HSTS check failed: " + str(e))    
    # Items not covered by this script:
    # - Incomplete certificate chain
    # - Deprecated signature algorithms (e.g., SHA-1)
    # - Certificate revocation issues (OCSP, CRL)
    # - Vulnerabilities to specific attacks (POODLE, BEAST)
    # - Underlying SSL/TLS library vulnerabilities (e.g., Heartbleed)
    # - Use of default or poorly managed certificates
    if errors:
        return "Errors detected: " + "; ".join(errors)
    # else:
    #     return "No SSL/TLS errors detected."

def debug_check_ssl(website, port=443):
    result = check_ssl_certificate(website, port=port)
    # Print out the website and the result that will be stored in the CSV
    print(f"Website: {website} --> Result: {result}")
    return result

def https_diagnostic_output(df):
    """
    Processes the DataFrame by checking the SSL certificate for each website
    listed in column 'P' and storing the result in column 'AM'.
    Parameters:
        df (pd.DataFrame): DataFrame containing at least columns 'P' (websites).
    Returns:
        pd.DataFrame: The updated DataFrame with a new column 'AM' containing 
                      the SSL certificate check results.
    """
    # Apply the check_ssl_certificate function on each website in column 'P'
    # df['https_diagnostic'] = df['website_url'].apply(lambda website: check_ssl_certificate(website, port=443) if pd.notnull(website) else None)
    # df['AM'] = df['P'].apply(lambda website: check_ssl_certificate(website, port=443) if pd.notnull(website) else None)
    df['https_diagnostic'] = df['website_url'].apply(
        lambda website: debug_check_ssl(website, port=443) if pd.notnull(website) else None
    )
    return df


if __name__ == "__main__":
    # host = "http://www.plexicus.com"  # Change to the target host
    # result = check_ssl_certificate(host)
    # print(result)
    
    # https_diagnostic_output()

    df = pd.read_csv('../data/lead-list1.csv')
    print("Columns in CSV:", df.columns.tolist())
    print(df.head())