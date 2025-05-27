# app.py
import ssl
import socket
import requests
from flask import Flask, render_template, request, jsonify
import OpenSSL.crypto
import OpenSSL.SSL
import json
import traceback
import datetime
import ipaddress # NEW: Import ipaddress for IP validation

# NEW: Import cryptography modules for X.509 extensions
from cryptography import x509
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

def get_extension_value(x509_cert, extension_name):
    """Helper to get an extension value by name."""
    for i in range(x509_cert.get_extension_count()):
        # FIX: Changed x509.get_extension(i) to x509_cert.get_extension(i)
        ext = x509_cert.get_extension(i)
        if ext.get_short_name() == extension_name:
            return ext
    return None

def parse_key_usage(x509_cert):
    """Parses the Key Usage extension from an X.509 certificate."""
    try:
        # Convert pyOpenSSL X509 object to cryptography X509 object
        cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, x509_cert)
        cryptography_cert = x509.load_pem_x509_certificate(cert_pem)

        key_usage_ext = cryptography_cert.extensions.get_extension_for_class(x509.KeyUsage)
        key_usages = []
        if key_usage_ext:
            ku = key_usage_ext.value
            # Use getattr to safely check for and access boolean flags
            if getattr(ku, 'digital_signature', False): key_usages.append("Digital Signature")
            if getattr(ku, 'non_repudiation', False): key_usages.append("Non Repudiation")
            if getattr(ku, 'key_encipherment', False): key_usages.append("Key Encipherment")
            if getattr(ku, 'data_encipherment', False): key_usages.append("Data Encipherment")
            if getattr(ku, 'key_agreement', False): key_usages.append("Key Agreement")

            # Only check encipher_only and decipher_only if key_agreement is true
            if getattr(ku, 'key_agreement', False):
                if getattr(ku, 'encipher_only', False): key_usages.append("Encipher Only")
                if getattr(ku, 'decipher_only', False): key_usages.append("Decipher Only")

            if getattr(ku, 'key_cert_sign', False): key_usages.append("Key Cert Sign")
            if getattr(ku, 'crl_sign', False): key_usages.append("CRL Sign")

        return ", ".join(key_usages) if key_usages else "N/A"
    except x509.ExtensionNotFound:
        return "N/A (Extension not found)"
    except Exception as e:
        return f"Error parsing Key Usage: {e}"

def parse_extended_key_usage(x509_cert):
    """Parses the Extended Key Usage extension from an X.509 certificate."""
    try:
        cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, x509_cert)
        cryptography_cert = x509.load_pem_x509_certificate(cert_pem)

        extended_key_usage_ext = cryptography_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        extended_key_usages = []
        if extended_key_usage_ext:
            for oid in extended_key_usage_ext.value:
                # Try to get the human-readable name, fallback to dotted string
                extended_key_usages.append(oid.name if hasattr(oid, 'name') else oid.dotted_string)
        return ", ".join(extended_key_usages) if extended_key_usages else "N/A"
    except x509.ExtensionNotFound:
        return "N/A (Extension not found)"
    except Exception as e:
        return f"Error parsing Extended Key Usage: {e}"

def get_crl_distribution_points(x509_cert):
    """
    Extracts CRL Distribution Point URLs from a certificate.
    Returns a list of URLs.
    """
    crl_urls = []
    crl_ext = get_extension_value(x509_cert, b'crlDistributionPoints')
    if crl_ext:
        crl_value = str(crl_ext)
        for line in crl_value.splitlines():
            if "URI:" in line:
                url = line.split("URI:")[1].strip()
                crl_urls.append(url)
    return crl_urls

def get_ssl_info(hostname, port=443):
    """
    Connects to the given hostname and port, retrieves the SSL certificate chain,
    and extracts basic information along with revocation status.
    """
    context = ssl.create_default_context()

    # Determine if hostname is an IP address
    is_ip_address = False
    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        # Not an IP address, proceed as a hostname
        pass

    # Set server_hostname for SNI. If it's an IP, SNI is generally not used,
    # and passing the IP as server_hostname can sometimes cause validation issues
    # if the certificate doesn't have the IP in its SANs (which is common).
    # Setting it to None prevents SNI from being sent.
    sni_hostname = None if is_ip_address else hostname

    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            # Use sni_hostname for server_hostname parameter
            with context.wrap_socket(sock, server_hostname=sni_hostname) as ssock:
                cert_chain_der = ssock.getpeercert(binary_form=True)

                if isinstance(cert_chain_der, bytes):
                    cert_chain_list = [cert_chain_der]
                elif isinstance(cert_chain_der, (tuple, list)):
                    cert_chain_list = list(cert_chain_der)
                else:
                    raise TypeError(f"Unexpected type for certificate chain: {type(cert_chain_der)}")

                certs_x509 = []
                for cert_der in cert_chain_list:
                    certs_x509.append(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der))

                if not certs_x509:
                    raise ValueError("No certificates found in the chain.")

                leaf_cert = certs_x509[0]
                issuer_cert = None
                if len(certs_x509) > 1:
                    issuer_cert = certs_x509[1]

                subject = dict(leaf_cert.get_subject().get_components())
                issuer = dict(leaf_cert.get_issuer().get_components())

                subject_decoded = {k.decode('utf-8'): v.decode('utf-8') for k, v in subject.items()}
                issuer_decoded = {k.decode('utf-8'): v.decode('utf-8') for k, v in issuer.items()}

                not_before_raw = leaf_cert.get_notBefore().decode('utf-8')
                not_after_raw = leaf_cert.get_notAfter().decode('utf-8')

                date_format_in = "%Y%m%d%H%M%SZ"
                date_format_out = "%d-%m-%Y %H:%M:%S"

                try:
                    dt_object_from = datetime.datetime.strptime(not_before_raw, date_format_in)
                    not_before = dt_object_from.strftime(date_format_out)
                except ValueError:
                    not_before = not_before_raw

                try:
                    dt_object_until = datetime.datetime.strptime(not_after_raw, date_format_in)
                    not_after = dt_object_until.strftime(date_format_out)
                except ValueError:
                    not_after = not_after_raw

                sans = []
                san_ext = get_extension_value(leaf_cert, b'subjectAltName')
                if san_ext:
                    san_value = str(san_ext)
                    for item in san_value.split(', '):
                        if item.startswith('DNS:'):
                            sans.append(item[4:])
                        # Also capture IP addresses from SANs if present
                        elif item.startswith('IP Address:'):
                            sans.append(item[11:])


                pub_key = leaf_cert.get_pubkey()
                pub_key_type = "RSA" if pub_key.type() == OpenSSL.crypto.TYPE_RSA else \
                               "DSA" if pub_key.type() == OpenSSL.crypto.TYPE_DSA else "Unknown"
                pub_key_bits = pub_key.bits()

                ocsp_status = "N/A (OCSP check disabled)"
                ocsp_url = "N/A"

                crl_urls = get_crl_distribution_points(leaf_cert)

                key_usage = parse_key_usage(leaf_cert)
                extended_key_usage = parse_extended_key_usage(leaf_cert)

                return {
                    "status": "success",
                    "hostname": hostname,
                    "subject": subject_decoded,
                    "issuer": issuer_decoded,
                    "valid_from": not_before,
                    "valid_until": not_after,
                    "serial_number": hex(leaf_cert.get_serial_number())[2:],
                    "version": str(leaf_cert.get_version()),
                    "fingerprint_sha256": leaf_cert.digest('sha256').decode('utf-8'),
                    "public_key_type": pub_key_type,
                    "public_key_bits": str(pub_key_bits),
                    "subject_alternative_names": sans,
                    "ocsp_status": ocsp_status,
                    "ocsp_url": ocsp_url,
                    "crl_distribution_points": crl_urls,
                    "key_usage": key_usage,
                    "extended_key_usage": extended_key_usage,
                }
    except ssl.SSLError as e:
        print("----- FULL TRACEBACK START (SSL Error) -----")
        traceback.print_exc()
        print("----- FULL TRACEBACK END (SSL Error) -----")
        return {"status": "error", "message": f"SSL Error: {e}. This might indicate a problem with the certificate itself or the SSL handshake."}
    except socket.gaierror:
        print("----- FULL TRACEBACK START (Socket GAIA Error) -----")
        traceback.print_exc()
        print("----- FULL TRACEBACK END (Socket GAIA Error) -----")
        return {"status": "error", "message": f"Hostname '{hostname}' could not be resolved. Please check the domain name."}
    except socket.timeout:
        print("----- FULL TRACEBACK START (Socket Timeout Error) -----")
        traceback.print_exc()
        print("----- FULL TRACEBACK END (Socket Timeout Error) -----")
        return {"status": "error", "message": f"Connection to '{hostname}' timed out. The server might be unreachable or too slow."}
    except ConnectionRefusedError:
        print("----- FULL TRACEBACK START (Connection Refused Error) -----")
        traceback.print_exc()
        print("----- FULL TRACEBACK END (Connection Refused Error) -----")
        return {"status": "error", "message": f"Connection to '{hostname}' refused. Is the server running and accessible on port {port}?"}
    except Exception as e:
        print("----- FULL TRACEBACK START (General Exception) -----")
        traceback.print_exc()
        print("----- FULL TRACEBACK END (General Exception) -----")
        return {"status": "error", "message": f"An unexpected error occurred: {e}. Please try again or check the domain."}

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Handles the main page requests.
    GET: Displays the form.
    POST: Processes the form submission and displays SSL info.
    """
    ssl_info = None
    hostname_searched = ''
    error = None

    if request.method == 'POST':
        hostname = request.form.get('hostname')
        if not hostname:
            error = "Please enter a hostname to analyze."
        else:
            ssl_info = get_ssl_info(hostname)
            hostname_searched = hostname
            if ssl_info and ssl_info.get('status') == 'error':
                error = ssl_info['message']
                ssl_info = None # Clear ssl_info if there was an error

    return render_template('index.html', ssl_info=ssl_info, hostname_searched=hostname_searched, error=error)

@app.route('/summarize_certificate', methods=['POST'])
def summarize_certificate():
    """
    New API endpoint to summarize certificate details using Gemini API.
    (This route is present but not used by the current HTML, kept for reference)
    """
    data = request.json
    ssl_data = data.get('ssl_info')

    if not ssl_data:
        return jsonify({"error": "No SSL info provided for summarization."}), 400

    prompt = f"""
    Summarize the following SSL/TLS certificate details in a concise, easy-to-understand paragraph.
    Focus on key aspects like:
    - Who issued it (Issuer Common Name, Organization)
    - To whom it was issued (Subject Common Name, Organization)
    - Its validity period (Valid From, Valid Until)
    - Any Subject Alternative Names (SANs) it covers.
    - Its OCSP status and CRL distribution points (if available).
    - Briefly mention the public key type and bits.
    - Key Usage: {ssl_data.get('key_usage', 'N/A')}
    - Extended Key Usage: {ssl_data.get('extended_key_usage', 'N/A')}

    Certificate Details:
    Hostname: {ssl_data.get('hostname', 'N/A')}
    Subject: {ssl_data.get('subject', 'N/A')}
    Issuer: {ssl_data.get('issuer', 'N/A')}
    Valid From: {ssl_data.get('valid_from', 'N/A')}
    Valid Until: {ssl_data.get('valid_until', 'N/A')}
    Serial Number: {ssl_data.get('serial_number', 'N/A')}
    SHA256 Fingerprint: {ssl_data.get('fingerprint_sha256', 'N/A')}
    Public Key Type: {ssl_data.get('public_key_type', 'N/A')}
    Public Key Bits: {ssl_data.get('public_key_bits', 'N/A')}
    Subject Alternative Names (SANs): {', '.join(ssl_data.get('subject_alternative_names', ['N/A']))}
    OCSP Status: {ssl_data.get('ocsp_status', 'N/A')}
    OCSP URL: {ssl_data.get('ocsp_url', 'N/A')}
    CRL Distribution Points: {', '.join(ssl_data.get('crl_distribution_points', ['N/A']))}

    Provide the summary in a friendly and informative tone, suitable for a general audience.
    """

    try:
        chatHistory = []
        chatHistory.append({ "role": "user", "parts": [{ "text": prompt }] })
        payload = { "contents": chatHistory }
        apiKey = "" # Canvas will provide this at runtime
        apiUrl = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={apiKey}" # Corrected: Removed '$' from f-string

        response = requests.post(apiUrl, json=payload, timeout=30)
        response.raise_for_status()

        result = response.json()

        if result.get('candidates') and result['candidates'][0].get('content') and result['candidates'][0]['content'].get('parts'):
            summary = result['candidates'][0]['content']['parts'][0]['text']
            return jsonify({"summary": summary})
        else:
            return jsonify({"error": "Gemini API response format unexpected."}), 500

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to call Gemini API: {e}"}), 500
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred during summarization: {e}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
