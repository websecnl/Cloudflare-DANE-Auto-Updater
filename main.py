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
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def log_result(old_hash, new_hash, result, additional_info=None):
    log_message = f"Old Hash Value: {old_hash}, New Hash Value: {new_hash}, Result: {result}"
    if additional_info:
        log_message += f", Additional Info: {additional_info}"
    logging.info(log_message)

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
    logging.info(f"Generated public_key_hash: {hash_sha256}")  # Log the generated hash for verification
    return hash_sha256

def fetch_and_select_tlsa_record(api_token, zone_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=TLSA"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200 and response.json().get('success'):
        records = response.json().get('result', [])
        if records:
            for i, record in enumerate(records, start=1):
                print(f"{i}. {record['name']} (ID: {record['id']}): {record['content']}")
            choice = int(input("Enter the number of the TLSA record you wish to update: ")) - 1
            return records[choice]['id']
        else:
            logging.info("No TLSA records found.")
            return None
    else:
        logging.error("Failed to fetch TLSA records.")
        return None

def update_cloudflare_dns(api_token, zone_id, dns_record_id, record_name, public_key_hash):
    logging.info(f"Using public_key_hash for update: {public_key_hash}")  # Log for verification
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{dns_record_id}"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    data = {
        "type": "TLSA",
        "name": record_name,
        "ttl": 1,
        "data": {
            "usage": 3,
            "selector": 1,
            "matching_type": 1,
            "certificate": public_key_hash
        }
    }

    response = requests.put(url, json=data, headers=headers)
    logging.info(f"Cloudflare DNS update (overwrite) response: Status Code: {response.status_code}, Content: {response.json()}")
    return response.status_code, response.json()

def main():
    config = configparser.ConfigParser()
    config_path = os.path.join(script_dir, 'config.ini')
    config.read(config_path)

    api_token = config['API']['token']
    zone_id = config['Cloudflare']['zone_id']
    hostname = config['TLSA']['hostname']
    port = 443
    dns_record_id = config['TLSA'].get('dns_record_id')

    if not dns_record_id:
        dns_record_id = fetch_and_select_tlsa_record(api_token, zone_id)
        if dns_record_id:
            config.set('TLSA', 'dns_record_id', dns_record_id)
            with open(config_path, 'w') as configfile:
                config.write(configfile)
        else:
            print("Unable to find or select a TLSA record for update.")
            return

    record_name = f"_443._tcp.{hostname}"
    certificate = get_tls_certificate(hostname, port)
    public_key_hash = get_public_key_hash(certificate)
    latest_value = config['TLSA'].get('latest_value', '')

    if latest_value != public_key_hash:
        status_code, response = update_cloudflare_dns(api_token, zone_id, dns_record_id, record_name, public_key_hash)
        if status_code == 200 and response['success'] and 'result' in response and response['result'].get('data', {}).get('certificate') == public_key_hash:
            config.set('TLSA', 'latest_value', public_key_hash)
            with open(config_path, 'w') as configfile:
                config.write(configfile)
            log_result(latest_value, public_key_hash, "Changed", additional_info=f"Cloudflare Update Response: {response}")
        else:
            log_result(latest_value, public_key_hash, "Failed to change", additional_info=f"Cloudflare Update Response: {response}")
    else:
        log_result(latest_value, public_key_hash, "Unchanged")

if __name__ == "__main__":
    main()
