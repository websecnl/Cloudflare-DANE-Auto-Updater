import socket
import ssl
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography import x509

def get_tls_certificate(host, port):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
    conn.connect((host, port))
    cert = conn.getpeercert(binary_form=True)
    conn.close()
    return cert

def get_public_key_hash(certificate):
    cert = x509.load_der_x509_certificate(certificate)
    public_key = cert.public_key()
    # Serialize the public key to bytes
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Hash the serialized public key
    hash_sha256 = hashlib.sha256(public_key_bytes).hexdigest()
    return hash_sha256

def generate_tlsa_record(hostname, port, public_key_hash):
    tlsa_record = f"_443._tcp.{hostname} IN TLSA 3 1 1 {public_key_hash}"
    return tlsa_record

# Replace 'websec.nl' with the domain you're interested in
hostname = 'websec.nl'
port = 443

certificate = get_tls_certificate(hostname, port)
public_key_hash = get_public_key_hash(certificate)
tlsa_record = generate_tlsa_record(hostname, port, public_key_hash)

print(f"TLSA Record for {hostname}:")
print(tlsa_record)
