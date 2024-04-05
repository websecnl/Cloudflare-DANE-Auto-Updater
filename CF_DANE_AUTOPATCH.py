
import configparser
import socket
import ssl
import hashlib
import requests
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import os
import logging

# Setup script directory and logging
script_dir = os.path.dirname(os.path.abspath(__file__))
log_file = os.path.join(script_dir, 'history.log')
logging.basicConfig(filename=log_file, level=logging.INFO,
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def log_result(old_hash, new_hash, result):
    logging.info(f"Old Hash Value: {old_hash}, New Hash Value: {new_hash}, Result: {result}")

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
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hash_sha256 = hashlib.sha256(public_key_bytes).hexdigest()
    return hash_sha256

def verify_cloudflare_token(api_token):
    url = "https://api.cloudflare.com/client/v4/user/tokens/verify"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers)
    return response.status_code == 200 and response.json().get('success')

def fetch_and_list_tlsa_records(api_token, zone_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=TLSA"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200 and response.json().get('success'):
        tlsa_records = response.json().get('result', [])
        if not tlsa_records:
            logging.info("No TLSA records found.")
            return None
        for i, record in enumerate(tlsa_records, start=1):
            print(f"{i}. {record['name']} (ID: {record['id']})")
        return tlsa_records
    else:
        logging.error("Failed to fetch TLSA records.")
        return None

def update_cloudflare_dns(api_token, zone_id, dns_record_id, record_name, new_tlsa_value):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{dns_record_id}"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    data = {
        "type": "TLSA",
        "name": record_name,
        "content": new_tlsa_value
    }
    response = requests.patch(url, json=data, headers=headers)
    return response.status_code, response.json()

def main():
    config = configparser.ConfigParser()
    config_path = os.path.join(script_dir, 'config.ini')
    config.read(config_path)

    api_token = config['API']['token']
    if not verify_cloudflare_token(api_token):
        logging.error("Provided Cloudflare API token is invalid.")
        return

    zone_id = config['Cloudflare']['zone_id']
    hostname = config['TLSA']['hostname']
    selector = config['TLSA']['selector']
    record_name = f"{selector}.{hostname}"

    dns_record_id = config['TLSA'].get('dns_record_id')
    if not dns_record_id:
        tlsa_records = fetch_and_list_tlsa_records(api_token, zone_id)
        if tlsa_records:
            choice = int(input("Which TLSA ID would you like to save to config.ini? Enter the number: ")) - 1
            selected_record = tlsa_records[choice]
            config.set('TLSA', 'dns_record_id', selected_record['id'])
            with open(config_path, 'w') as configfile:
                config.write(configfile)
            logging.info(f"Selected TLSA record ID: {selected_record['id']} saved to config.ini.")
        else:
            return

    port = 443
    certificate = get_tls_certificate(hostname, port)
    public_key_hash = get_public_key_hash(certificate)
    latest_value = config['TLSA'].get('latest_value')
    result = "Unchanged"

    if latest_value != public_key_hash:
        status_code, response = update_cloudflare_dns(api_token, zone_id, dns_record_id, record_name, f"3 1 1 {public_key_hash}")
        if status_code == 200:
            config.set('TLSA', 'latest_value', public_key_hash)
            with open(config_path, 'w') as configfile:
                config.write(configfile)
            result = "Changed"
        else:
            result = "Error"
            logging.error(f"Failed to update TLSA record: {response}")

    log_result(latest_value, public_key_hash, result)

if __name__ == "__main__":
    main()
