# APP_VERSION_20250529_003 - This line indicates the latest code version.
import ssl
import socket
import requests
from flask import Flask, render_template, request, jsonify
import OpenSSL.crypto
import OpenSSL.SSL
import json
import traceback
import datetime
import ipaddress
import os # Added for OCSP nonce generation
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509 import load_der_x509_crl, RevokedCertificate
from cryptography.hazmat.primitives import hashes # For OCSP request builder

# Conditional import for OCSP to handle potential missing module gracefully
try:
    from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponse, OCSPResponseStatus, OCSPCertStatus
    OCSP_MODULE_AVAILABLE = True
except ImportError:
    OCSP_MODULE_AVAILABLE = False
    print("WARNING: cryptography.x509.ocsp module not found. OCSP checks will be disabled.")
except AttributeError: # Catch if OpenSSL.crypto.OCSP was the issue
    OCSP_MODULE_AVAILABLE = False
    print("WARNING: OpenSSL.crypto.OCSP attribute not found. OCSP checks will be disabled.")


app = Flask(__name__)

# Register a custom Jinja2 filter to parse JSON strings
@app.template_filter('from_json')
def from_json_filter(value):
    """Parses a JSON string into a Python object."""
    if value:
        return json.loads(value)
    return {}


def get_extension_value(x509_cert, extension_name):
    """Helper to get an extension value by name."""
    for i in range(x509_cert.get_extension_count()):
        ext = x509.Extension.from_asn1(x509.ObjectIdentifier(ext.get_oid()), ext.get_data()) # Convert to cryptography extension object
        if ext.oid.dotted_string == extension_name: # Use dotted_string for comparison
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
    # Convert pyOpenSSL X509 object to cryptography X509 object
    cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, x509_cert)
    cryptography_cert = x509.load_pem_x509_certificate(cert_pem)

    try:
        crl_dp_ext = cryptography_cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        for distribution_point in crl_dp_ext.value:
            if distribution_point.full_name and distribution_point.full_name[0].value:
                for general_name in distribution_point.full_name:
                    if isinstance(general_name, x509.UniformResourceIdentifier):
                        crl_urls.append(general_name.value)
    except x509.ExtensionNotFound:
        pass # No CRL Distribution Points extension
    except Exception as e:
        print(f"Error extracting CRL Distribution Points: {e}")
        traceback.print_exc()
    return crl_urls


def check_crl_revocation(crl_urls, certificate_serial):
    """
    Checks if a certificate is revoked by iterating through provided CRL URLs.
    Returns "Revoked", "Not Revoked", or "Unknown (Error/No CRLs)"
    """
    print(f"\n--- Starting CRL Revocation Check ---")
    print(f"Certificate Serial Number to check: {certificate_serial}")
    print(f"CRL Distribution Points found: {crl_urls}")

    if not crl_urls:
        print("No CRL Distribution Points found in certificate.")
        return "Unknown (No CRL Distribution Points)"

    # Convert serial number to integer for comparison
    cert_serial_int = int(certificate_serial, 16) # Assuming serial is hex string from app.py

    for crl_url in crl_urls:
        try:
            # Download CRL
            print(f"Attempting to download CRL from: {crl_url}")
            # CHANGED: Reduced timeout to 5 seconds
            response = requests.get(crl_url, timeout=5)
            response.raise_for_status() # Raise an exception for HTTP errors
            print(f"Successfully downloaded CRL from {crl_url}. Size: {len(response.content)} bytes.")

            # Parse CRL using cryptography
            crl_data = response.content
            crl = load_der_x509_crl(crl_data) # Use cryptography's load_der_x509_crl
            print(f"Successfully parsed CRL from {crl_url}.")

            # Check for revoked entries
            # In cryptography, crl.get_revoked_certificates() was deprecated.
            # Iterate through crl to find revoked certificates.
            found_revoked_cert = False
            for revoked_cert in crl: # Iterate directly over the CRL object
                revoked_serial = revoked_cert.serial_number # Serial is directly an integer now
                # Explicitly print both serials in hex and int for debugging
                print(f"  Comparing revoked serial (int): {revoked_serial} (hex: {hex(revoked_serial)}) with target serial (int): {cert_serial_int} (hex: {hex(cert_serial_int)})")
                if revoked_serial == cert_serial_int:
                    print(f"Certificate with serial {certificate_serial} IS REVOKED by CRL from {crl_url}.")
                    found_revoked_cert = True
                    break
            
            if found_revoked_cert:
                return "Revoked"
            else:
                print(f"CRL from {crl_url} checked. Certificate not found in this CRL.")


        except requests.exceptions.RequestException as e:
            print(f"Error downloading CRL from {crl_url}: {e}")
            # Continue to next URL if one fails
        except Exception as e: # Catch all exceptions during CRL parsing/check
            print(f"An unexpected error occurred during CRL check for {crl_url}: {e}")
            traceback.print_exc() # Print full traceback for deeper debugging
            # Continue to next URL if one fails

    print(f"--- Finished CRL Revocation Check. Certificate NOT found revoked in any available CRL. ---")
    return "Not Revoked (Checked all available CRLs)"

def check_ocsp_revocation(ocsp_urls, leaf_cert_pem, issuer_cert_pem):
    """
    Checks certificate revocation status using OCSP.
    Accepts PEM encoded certificates as strings.
    Returns "Revoked", "Not Revoked", or "Unknown (Error/No OCSP URLs)"
    """
    print(f"\n--- Starting OCSP Revocation Check ---")
    print(f"OCSP Responder URLs found: {ocsp_urls}")

    if not OCSP_MODULE_AVAILABLE:
        print("OCSP module not available, skipping OCSP check.")
        return "Unknown (OCSP module issue)"

    if not ocsp_urls or not issuer_cert_pem:
        print("No OCSP Responder URLs or issuer certificate not available for OCSP check.")
        return "Unknown (No OCSP URLs or Issuer Cert)"

    # Convert PEM certs to cryptography cert objects
    try:
        cryptography_leaf_cert = x509.load_pem_x509_certificate(leaf_cert_pem.encode('utf-8'))
        cryptography_issuer_cert = x509.load_pem_x509_certificate(issuer_cert_pem.encode('utf-8'))
        print(f"Leaf Certificate Serial Number (for OCSP request): {hex(cryptography_leaf_cert.serial_number)[2:]}")
        print(f"Issuer Certificate Subject (for OCSP request): {cryptography_issuer_cert.subject}")
        print(f"Issuer Certificate Serial Number (for OCSP request): {hex(cryptography_issuer_cert.serial_number)[2:]}")
    except Exception as e:
        print(f"Error converting certs to cryptography objects for OCSP: {e}")
        traceback.print_exc()
        return "Unknown (Cert Conversion Error)"

    # Create an OCSP request using cryptography
    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(
        cryptography_leaf_cert,
        cryptography_issuer_cert,
        hashes.SHA1()
    )
    # Add nonce for replay protection (optional but good practice)
    builder = builder.add_extension(
        x509.OCSPNonce(os.urandom(16)), critical=False
    )
    
    try:
        ocsp_req_der = builder.build().public_bytes(serialization.Encoding.DER)
    except Exception as e:
        print(f"Error building OCSP request DER: {e}")
        traceback.print_exc()
        return "Unknown (OCSP Request Build Error)"

    for ocsp_url in ocsp_urls:
        try:
            print(f"Attempting to send OCSP request to: {ocsp_url}")
            # CHANGED: Reduced timeout to 5 seconds
            response = requests.post(
                ocsp_url,
                data=ocsp_req_der,
                headers={'Content-Type': 'application/ocsp-request'},
                timeout=5
            )
            response.raise_for_status() # Raise an exception for HTTP errors
            print(f"Successfully received OCSP response from {ocsp_url}. Size: {len(response.content)} bytes.")

            # Parse OCSP response using cryptography
            ocsp_resp = OCSPResponse.load(response.content)

            # Check overall response status
            if ocsp_resp.response_status != OCSPResponseStatus.SUCCESSFUL:
                print(f"OCSP response status from {ocsp_url}: {ocsp_resp.response_status}")
                continue # Try next URL

            basic_ocsp_response = ocsp_resp.response_bytes # This is BasicOCSPResponse object
            
            # In cryptography, basic_ocsp_response.all_responses is a list of SingleResponse objects.
            for single_response in basic_ocsp_response.all_responses:
                cert_status = single_response.cert_status
                if cert_status == OCSPCertStatus.GOOD:
                    print(f"OCSP status for certificate from {ocsp_url}: GOOD")
                    return "Not Revoked"
                elif cert_status == OCSPCertStatus.REVOKED:
                    revocation_time = single_response.revocation_info.revocation_time
                    revocation_reason = single_response.revocation_info.revocation_reason
                    reason_str = revocation_reason.name if revocation_reason else "No reason specified"
                    print(f"OCSP status for certificate from {ocsp_url}: REVOKED at {revocation_time} (Reason: {reason_str})")
                    return "Revoked"
                elif cert_status == OCSPCertStatus.UNKNOWN:
                    print(f"OCSP status for certificate from {ocsp_url}: UNKNOWN")
                    # Continue to next URL if one returns unknown
            print(f"OCSP response from {ocsp_url} did not contain a definitive status for the target certificate.")

        except requests.exceptions.RequestException as e:
            print(f"Error communicating with OCSP responder {ocsp_url}: {e}")
            # Continue to next URL if one fails
        except Exception as e: # Catch all exceptions during OCSP parsing/check
            print(f"An unexpected error occurred during OCSP check for {ocsp_url}: {e}")
            traceback.print_exc() # Print full traceback for deeper debugging
            # Continue to next URL if one fails

    print(f"--- Finished OCSP Revocation Check. Certificate status UNKNOWN via OCSP. ---")
    return "Unknown (OCSP Check Failed or No Definitive Status)"

def check_blacklist_status(public_key_sha256):
    """
    Simulates checking a public key against a blacklist.
    In a real application, this would query a database of known compromised keys.
    Returns "Blacklisted", "Not Blacklisted", or "Unknown".
    """
    # --- SIMULATED BLACKLIST ---
    # These are example SHA256 hashes of public keys that might be considered blacklisted.
    # In a real scenario, this list would be extensive and regularly updated from a trusted source.
    simulated_blacklist = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", # Example: SHA256 of an empty string
        "2ed184c8a29a733792b0c16921316b1420a3d46376c667a42125f4f1a4e1a7b0", # Example: Placeholder 1
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", # Example: Placeholder 2
        # Add SHA256 of revoked.badssl.com's public key for testing
        # To get this:
        # 1. openssl s_client -connect revoked.badssl.com:443 -showcerts </dev/null 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256
        # The output might be different based on the exact certificate served at the time.
        # For 'revoked.badssl.com', the public key SHA256 is typically:
        "4b4904269389e47f7733f114c516315570894087b2e3f511210214c776097561" # Example SHA256 for revoked.badssl.com's public key (replace with actual if needed)
    ]
    # Remove "sha256:" prefix if present for consistent comparison
    cleaned_public_key_sha256 = public_key_sha256.replace("sha256:", "")

    if cleaned_public_key_sha256 in [h.replace("sha256:", "") for h in simulated_blacklist]:
        return "Blacklisted"
    return "Not Blacklisted"


def get_ssl_info(hostname, port=443):
    """
    Connects to the given hostname and port, retrieves the SSL certificate chain,
    and extracts basic information. Revocation checks are now separate.
    """
    context = ssl.create_default_context()

    is_ip_address = False
    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        pass

    sni_hostname = None if is_ip_address else hostname

    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=sni_hostname) as ssock:
                cert_chain_der = ssock.getpeercert(binary_form=True)

                if isinstance(cert_chain_der, bytes):
                    cert_chain_list = [cert_chain_der]
                elif isinstance(cert_chain_der, (tuple, list)):
                    cert_chain_list = list(cert_chain_der)
                else:
                    raise TypeError(f"Unexpected type for certificate chain: {type(cert_chain_der)}")

                certs_x509 = []
                print("\n--- Certificate Chain Retrieved ---")
                for i, cert_der in enumerate(cert_chain_list):
                    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
                    certs_x509.append(cert)
                    print(f"Certificate {i}:")
                    print(f"  Subject: {dict(cert.get_subject().get_components())}")
                    print(f"  Issuer: {dict(cert.get_issuer().get_components())}")
                    print(f"  Serial: {hex(cert.get_serial_number())[2:]}")
                print("--- End Certificate Chain ---")

                if not certs_x509:
                    raise ValueError("No certificates found in the chain.")

                leaf_cert = certs_x509[0]
                issuer_cert = None
                for i in range(1, len(certs_x509)):
                    if certs_x509[i].get_subject() == leaf_cert.get_issuer():
                        issuer_cert = certs_x509[i]
                        print("\nDirect issuer certificate found in provided chain.")
                        break
                
                if issuer_cert is None:
                    print("\nDirect issuer certificate NOT found in provided chain. Attempting to fetch via AIA.")
                    cert_pem_for_cryptography = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, leaf_cert)
                    cryptography_leaf_cert = x509.load_pem_x509_certificate(cert_pem_for_cryptography)

                    ca_issuers_urls = []
                    try:
                        aia_ext = cryptography_leaf_cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
                        for access_description in aia_ext.value:
                            if access_description.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                                ca_issuers_urls.append(access_description.access_location.value)
                        
                        if ca_issuers_urls:
                            print(f"CA Issuers URLs found in AIA: {ca_issuers_urls}")
                            for ca_url in ca_issuers_urls:
                                try:
                                    print(f"Attempting to download issuer certificate from AIA: {ca_url}")
                                    response = requests.get(ca_url, timeout=5)
                                    response.raise_for_status()
                                    downloaded_issuer_cert = OpenSSL.crypto.load_certificate(
                                        OpenSSL.crypto.FILETYPE_ASN1, response.content
                                    )
                                    if downloaded_issuer_cert.get_subject() == leaf_cert.get_issuer():
                                        issuer_cert = downloaded_issuer_cert
                                        print(f"Successfully downloaded and identified issuer certificate from AIA: {ca_url}")
                                        break
                                    else:
                                        print(f"Downloaded certificate from {ca_url} is not the expected issuer.")
                                except requests.exceptions.RequestException as e:
                                    print(f"Error downloading issuer cert from {ca_url} via AIA: {e}")
                                except OpenSSL.crypto.Error as e:
                                    print(f"Error parsing downloaded issuer cert from {ca_url}: {e}")
                                except Exception as e:
                                    print(f"An unexpected error during AIA issuer fetch from {ca_url}: {e}")
                        else:
                            print("No CA Issuers URLs found in AIA extension.")
                    except x509.ExtensionNotFound:
                        print("Authority Information Access extension not found in leaf certificate.")

                leaf_cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, leaf_cert).decode('utf-8')
                issuer_cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, issuer_cert).decode('utf-8') if issuer_cert else None

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
                cryptography_cert_for_sans = x509.load_pem_x509_certificate(leaf_cert_pem.encode('utf-8'))

                try:
                    san_ext = cryptography_cert_for_sans.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    for general_name in san_ext.value:
                        if isinstance(general_name, x509.DNSName):
                            sans.append(general_name.value)
                        elif isinstance(general_name, x509.IPAddress):
                            sans.append(str(general_name.value))
                except x509.ExtensionNotFound:
                    pass

                ocsp_urls = []
                try:
                    aia_ext = cryptography_cert_for_sans.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
                    for access_description in aia_ext.value:
                        if access_description.access_method == AuthorityInformationAccessOID.OCSP:
                            ocsp_urls.append(access_description.access_location.value)
                except x509.ExtensionNotFound:
                    pass

                pub_key = leaf_cert.get_pubkey()
                pub_key_type = "RSA" if pub_key.type() == OpenSSL.crypto.TYPE_RSA else \
                               "DSA" if pub_key.type() == OpenSSL.crypto.TYPE_DSA else "Unknown"
                pub_key_bits = pub_key.bits()

                # Get public key DER bytes and calculate SHA256 fingerprint
                public_key_crypto = pub_key.to_cryptography_key()
                public_key_der = public_key_crypto.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                public_key_sha256_hasher = hashes.Hash(hashes.SHA256())
                public_key_sha256_hasher.update(public_key_der)
                public_key_fingerprint = public_key_sha256_hasher.finalize().hex()

                # Check blacklist status
                blacklist_status = check_blacklist_status(public_key_fingerprint)


                crl_urls = get_crl_distribution_points(leaf_cert)
                certificate_serial = hex(leaf_cert.get_serial_number())[2:]

                key_usage = parse_key_usage(leaf_cert)
                extended_key_usage = parse_extended_key_usage(leaf_cert)

                return {
                    "status": "success",
                    "hostname": hostname,
                    "subject": subject_decoded,
                    "issuer": issuer_decoded,
                    "valid_from": not_before,
                    "valid_until": not_after,
                    "serial_number": certificate_serial,
                    "version": str(leaf_cert.get_version()),
                    "fingerprint_sha256": leaf_cert.digest('sha256').decode('utf-8'),
                    "public_key_type": pub_key_type,
                    "public_key_bits": str(pub_key_bits),
                    "public_key_blacklist_status": blacklist_status, # Added blacklist status
                    "subject_alternative_names": sans,
                    "ocsp_url": ocsp_urls[0] if ocsp_urls else "N/A",
                    "ocsp_urls_all": ocsp_urls,
                    "crl_distribution_points": crl_urls,
                    "leaf_cert_pem": leaf_cert_pem,
                    "issuer_cert_pem": issuer_cert_pem,
                    "key_usage": key_usage,
                    "extended_key_usage": extended_key_usage
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

@app.route('/', methods=['GET'])
def index():
    """
    Handles the main page GET request, rendering the initial form.
    """
    return render_template('index.html', hostname_searched='', error=None)

@app.route('/analyze_ssl_api', methods=['POST'])
def analyze_ssl_api():
    """
    New API endpoint to asynchronously get SSL certificate information.
    """
    data = request.json
    hostname = data.get('hostname')

    if not hostname:
        return jsonify({"status": "error", "message": "Hostname is required for analysis."}), 400

    ssl_info_result = get_ssl_info(hostname)
    return jsonify(ssl_info_result)


@app.route('/get_revocation_status', methods=['POST'])
def get_revocation_status():
    """
    New API endpoint to asynchronously get OCSP and CRL revocation status.
    """
    data = request.json
    serial_number = data.get('serial_number')
    ocsp_urls = data.get('ocsp_urls_all', [])
    crl_urls = data.get('crl_distribution_points', [])
    leaf_cert_pem = data.get('leaf_cert_pem')
    issuer_cert_pem = data.get('issuer_cert_pem')

    if not serial_number or not leaf_cert_pem:
        return jsonify({"error": "Missing required certificate data for revocation check."}), 400

    ocsp_status = "Unknown (Not Checked)"
    crl_status = "Unknown (Not Checked)"

    try:
        ocsp_status = check_ocsp_revocation(ocsp_urls, leaf_cert_pem, issuer_cert_pem)
    except Exception as e:
        print(f"Error during OCSP check in /get_revocation_status: {e}")
        traceback.print_exc()
        ocsp_status = f"Error: {e}"

    try:
        crl_status = check_crl_revocation(crl_urls, serial_number)
    except Exception as e:
        print(f"Error during CRL check in /get_revocation_status: {e}")
        traceback.print_exc()
        crl_status = f"Error: {e}"

    return jsonify({
        "ocsp_status": ocsp_status,
        "crl_revocation_status": crl_status
    })


@app.route('/summarize_certificate', methods=['POST'])
def summarize_certificate():
    """
    New API endpoint to summarize certificate details using Gemini API.
    """
    data = request.json
    ssl_data = data.get('ssl_info')

    if not ssl_data:
        return jsonify({"error": "No SSL info provided for summarization."}), 400

    ocsp_status_for_summary = ssl_data.get('ocsp_status', 'N/A')
    crl_revocation_status_for_summary = ssl_data.get('crl_revocation_status', 'N/A')
    public_key_blacklist_status = ssl_data.get('public_key_blacklist_status', 'N/A') # Get blacklist status

    is_expired = "No"
    try:
        valid_until_str = ssl_data.get('valid_until', '')
        if valid_until_str and valid_until_str != 'N/A':
            valid_until_dt = datetime.datetime.strptime(valid_until_str, "%d-%m-%Y %H:%M:%S")
            if datetime.datetime.now() > valid_until_dt:
                is_expired = "Yes"
    except ValueError:
        is_expired = "Unknown (Date Parse Error)"

    is_self_signed = "No"
    if ssl_data.get('subject') and ssl_data.get('issuer'):
        if ssl_data['subject'] == ssl_data['issuer']:
            is_self_signed = "Yes"

    hostname_mismatch = "No"
    requested_hostname = ssl_data.get('hostname', '').lower()
    subject_cn = ssl_data.get('subject', {}).get('CN', '').lower()
    sans = [s.lower() for s in ssl_data.get('subject_alternative_names', [])]

    if requested_hostname and not (requested_hostname == subject_cn or any(requested_hostname == s or (s.startswith('*.') and requested_hostname.endswith(s[1:])) for s in sans)):
        hostname_mismatch = "Yes"


    prompt = f"""
    Provide a very concise, simple summary of the SSL/TLS certificate for {ssl_data.get('hostname', 'N/A')}.
    Focus on major security issues or vulnerabilities. If no major issues are found, state that the certificate appears valid and secure.

    Key details for analysis:
    - Certificate expiration: Valid until {ssl_data.get('valid_until', 'N/A')} (Is expired: {is_expired})
    - OCSP Status: {ocsp_status_for_summary}
    - CRL Revocation Status: {crl_revocation_status_for_summary}
    - Public Key: {ssl_data.get('public_key_type', 'N/A')} with {ssl_data.get('public_key_bits', 'N/A')} bits.
    - Public Key Blacklist Status: {public_key_blacklist_status}
    - Is Self-Signed: {is_self_signed}
    - Issuer Common Name: {ssl_data.get('issuer', {}).get('CN', 'N/A')}
    - Subject Alternative Names (SANs): {', '.join(ssl_data.get('subject_alternative_names', ['N/A']))}
    - Hostname Mismatch: {hostname_mismatch}

    Based on the provided details, here are the key findings:
    - If "Is expired" is "Yes": The certificate is expired, making it untrustworthy.
    - If OCSP Status is "Revoked" or CRL Revocation Status is "Revoked": The certificate has been explicitly revoked, indicating it should no longer be trusted.
    - If OCSP Status is "Not Revoked" AND CRL Revocation Status is "Not Revoked (Checked all available CRLs)": The certificate's revocation status appears good.
    - If OCSP Status is "Unknown (OCSP Check Failed or No Definitive Status)" or CRL Revocation Status is "Unknown (No CRL Distribution Points)": The certificate's revocation status could not be definitively determined, which is a security concern.
    - If Public Key Bits are less than 2048 for RSA keys: The public key is weak and vulnerable to brute-force attacks.
    - If Public Key Blacklist Status is "Blacklisted": The public key is known to be compromised, posing a severe security risk.
    - If "Hostname Mismatch" is "Yes": The certificate does not cover the requested hostname, leading to trust warnings.
    - If "Is Self-Signed" is "Yes": The certificate is self-signed, meaning it's not issued by a trusted Certificate Authority and will cause trust warnings in browsers.
    - If the Issuer Common Name does not appear to be from a widely recognized public Certificate Authority (e.g., Let's Encrypt, DigiCert, GlobalSign, Sectigo, Google Trust Services, Cloudflare, Amazon, Microsoft, Apple), or if it looks like a private/internal CA: The certificate is signed by an untrusted or unknown CA, which will lead to trust warnings.

    Keep the summary to 2-3 sentences maximum. Start directly with the most critical finding.
    """

    apiKey = "*************" # If you want to use models other than gemini-2.0-flash or imagen-3.0-generate-002, provide an API key here. Otherwise, leave this as-is.
    if not apiKey:
        return jsonify({"error": "Gemini API Key is not configured in app.py"}), 500

    apiUrl = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={apiKey}"

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ]
    }

    try:
        response = requests.post(apiUrl, json=payload, timeout=30)
        response.raise_for_status()
        result = response.json()

        if result and result.get('candidates') and result['candidates'][0].get('content') and result['candidates'][0]['content'].get('parts'):
            summary = result['candidates'][0]['content']['parts'][0]['text']
            return jsonify({"summary": summary})
        else:
            print(f"Unexpected Gemini API response structure: {json.dumps(result, indent=2)}")
            return jsonify({"error": "Unexpected response from Gemini API."}), 500

    except requests.exceptions.RequestException as e:
        print(f"Gemini API request failed: {e}")
        traceback.print_exc()
        return jsonify({"error": f"Failed to call Gemini API: {e}. Check network and API key."}), 500
    except Exception as e:
        print(f"An unexpected error occurred during summarization: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred during summarization: {e}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
