#!/usr/bin/env python3

import ngrok
import zipfile
import subprocess
import os
import tempfile
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from time import sleep


def check_config():
    status = True
    config_entries = [
        'HANDSHAKE_LOCATION', 
        'NGROK_API_KEY', 
        'SMTP_PASS', 
        'SMTP_PORT', 
        'SMTP_SERVER', 
        'SMTP_USER', 
        'SSH_USERNAME', 
        'WORDLISTS_LOCATION'
    ]

    for entry in config_entries:
        if entry not in dir(config):
            print(f"[X] {entry} is not set in the config.py file.")
            exit(0)

    if len(config.NGROK_API_KEY) == 0:
        print("[X] NGROK_API_KEY not specified")
        status = False

    elif len(config.SSH_USERNAME) == 0:
        print("[X] SSH_USERNAME not specified")
        status = False

    elif len(config.HANDSHAKE_LOCATION) == 0:
        print("[X] HANDSHAKE_LOCATION not specified")
        status = False
    
    elif len(config.WORDLISTS_LOCATION) == 0:
        print("[X] WORDLISTS_LOCATION not specified")

    if not status:
        exit(0)


def get_ngrok_tunnels(ngrok_api_key):
    """get_ngrok_tunnels 
    use the ngrok api from https://api.ngrok.com to get the active ngrok tunnels

    Args:
        ngrok_api_key (str): The api key used to comunicate with the ngrok api.

    Returns:
        None: If there are no active tunnels, returns None
        List: If there are active tunnels, returns a List with tunnel dictionaries.

    Tunnel Dictionary Contains:
        tunnel_dict['forwards_to]: The ports where the tunnel is forwarding to.
        tunnel_dict['protocol']: The ngrok tunnel protocol.
        tunnel_dict['domain']: The ngrok tunnel domain name.
        tunnel_dict['port']: The ngrok tunnel port.
    """
    client = ngrok.Client(ngrok_api_key)
    tunnels = client.tunnels.list().tunnels
    
    if len(tunnels) == 0:
        return None
    else:
        result = list()
        for tunnel in tunnels:            
            # public_url = [protocol, domain, port]
            public_url = tunnel.public_url.replace("/", "").split(":")  
            
            tunnel_dict = dict()
            tunnel_dict['forwards_to'] = tunnel.forwards_to.split(":")[1]
            tunnel_dict['protocol'] = public_url[0]
            tunnel_dict['domain']   = public_url[1]
            tunnel_dict['port']     = public_url[2]
            result.append(tunnel_dict)

        return result
        

def get_hash(domain, port, user, handshake_path):
    """get_hash
    Connects to the specified domain via scp using the specified user and downloads the zip file that
    contains the hash or handshake_path
    

    Args:
        domain (str): domain to connect to.
        port (str): port to connect to.
        user (str): user used in the scp session.
        handshake_path (str): Path to the zip file that contains the hash to crack and the rules.

    Returns:
        bool: Returns True if success, otherwise returns False.
    """

    # Ensure the loot directory exists
    os.makedirs("./loot", exist_ok=True)

    result = subprocess.run(
        [
            "scp", "-o", "StrictHostKeyChecking=no", "-P", port, f"{user}@{domain}:{handshake_path}", "./loot/"
        ],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        return True
    else:
        return False


def extract_files_from_zip(path_to_zip):
    """this function extract the content of the files that are inside the zip (path_to_zip) 
    and write his content to temporary files for later use.

    The content of path_to_zip (RULES.txt) is stored in dict['rules']. (REQUIRED)
    The content of path_to_zip (wpa_handshake.pcap) is stored in dict['pcap'].

    Args:
        path_to_zip (str): Path to the zip file that contains RULES.txt and wpa_handshake.pcap

    Returns:
        dict: {'rules': <tempfile object>, 'pcap': <tempfile object>}
        None: If RULES.txt is not inside the zip file.
    """

    with zipfile.ZipFile(path_to_zip, "r") as zip_ref:
        zip_files = zip_ref.namelist()

        handshake = dict()
        if "RULES.txt" in zip_files:
            handshake['rules'] = tempfile.NamedTemporaryFile()
            with open(handshake['rules'].name, 'w') as rules:
                rules.write(zip_ref.read("RULES.txt").decode('utf-8'))

        if "wpa_handshake.pcap" in zip_files:
            handshake['pcap']  = tempfile.NamedTemporaryFile()
            with open(handshake["pcap"].name, "wb") as pcap:
                pcap.write(zip_ref.read("wpa_handshake.pcap"))

    if handshake.get("rules") is None:
        return None

    return handshake    


def parse_rules(rules:str):
    """parse rules from RULES.txt content
    To see the available rules, see Rules...

    Args:
        rules (str): The string content of the RULES.txt file.

    Returns:
        dict: Dictionary containing the parsed rules.
        None: If an invalid rule is specified, returns None.

    Rules:
        WORDLIST: 
            Specify the name of the wordlist. 
            Example: WORDLIST="rockyou.txt"

        CRUNCH: 
            If the specified wordlist doesnt exist, then create one with crunch.
            Example: CRUNCH="13 13 0123456789 -t WiFi-@@@@@@@@"

        STATUS_CHECK:
            If present in the RULES.txt file, then crackahash will send an email to
            config.SMTP_USER.
            Example: STATUS_CHECK="True"

    """
    lines = rules.splitlines()
    rules = [line for line in lines if line.strip() and not line.strip().startswith('#') ]

    parsed_rules = dict()
    for rule in rules:
        splitted_rule = rule.split("=")

        KEY, VALUE = splitted_rule[0], splitted_rule[1]

        if KEY == "WORDLIST":
            parsed_rules['wordlist'] = config.WORDLISTS_LOCATION + VALUE.replace("\"","")
        
        elif KEY == "CRUNCH":
            parsed_rules['crunch'] = VALUE.replace("\"","")

        elif KEY == "STATUS_CHECK":
            if VALUE.replace("\"","") == "True":
                parsed_rules['status_check'] = True
        
        else:
            return None
        
    return parsed_rules


def validate_rules(rules:dict):
    # validating wordlist
    if rules.get('wordlist') is not None and not os.path.exists(f"{rules['wordlist']}"):
        return 1


def pcap_to_hashcat(handshake:dict):
    """pcap_to_hashcat adds a new entry to the dictionary handshake.
    This new entry is another temporary file that contains the hashcat format
    of the pcap file.

    Here is what happen:

    # this is the new entry added to handshake dict()
    handshake['hashcat'] = tempfile.NamedTemporaryFile()

    # hcxpcapngtool transform a simple .pcap file into a file usable by hashcat
    $ hcxpcapngtool -o {handshake['hashcat'].name} {handshake['pcap'].name}

    Args:
        handshake (dict): _description_

    Returns:
        bool: True if everything executed successfully, False otherwise
    """
    # hcxpcapngtool -o hashfile.hc22000 -E essidlist wpa_handshake.pcap
    handshake['hashcat'] = tempfile.NamedTemporaryFile()
    result = subprocess.run(
        [
            "hcxpcapngtool", "-o", handshake['hashcat'].name, handshake['pcap'].name
        ], 
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        return True
    else:
        return False
    

def send_email(subject, body=""):
    """simply sends an email from config.SMTP_USER to config.SMTP_USER.

    Args:
        subject (str): message subject.
        body (str,optional): message body.

    Returns:
        bool: True if everything executed successfully, False otherwise.
    """

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = config.SMTP_USER
    msg['To'] = config.SMTP_USER

    status = True
    try:
        with smtplib.SMTP_SSL(config.SMTP_SERVER, config.SMTP_PORT) as smtp_server:
            smtp_server.login(config.SMTP_USER, config.SMTP_PASS)
            smtp_server.sendmail(config.SMTP_USER, [config.SMTP_USER], msg.as_string())
    except Exception as e:
        print("[X] Error while sending the email...")
        print(e)
        status = False
    
    return status


def run_hashcat(hash_file, wordlist):

    # checking if hash_file is already cracked
    try:
        command = [
            "hashcat",
            hash_file,
            "--show"
        ]
        result = subprocess.run(command, text=True, capture_output=True, check=True)
        if result.returncode == 0:
            return result.stdout
    except subprocess.CalledProcessError as e:
        result = "[X] Error while executing hashcat: " + "\n"
        result += e.output
        print(result)
        return result
    
    # cracking hash
    try:
        command = [
            "hashcat",
            "-m", "22000",
            hash_file,
            wordlist,
            "-d", "1",
            "--force"
        ]
        result = subprocess.run(command, text=True, capture_output=True, check=True)
        if result.returncode == 0:
            return result.stdout
    except subprocess.CalledProcessError as e:
        result = "[X] Error while executing hashcat: " + "\n"
        result += e.output
        print(result)
        return result
    
    return "NO HASH CRACKED :("
    


def main():
    check_config()

    while True:
        print("[!] Getting active ngrok tunnels")
        tunnels = get_ngrok_tunnels(config.NGROK_API_KEY)

        if tunnels is None:
            print("[X] No tunnels open, waiting until the next retry...")
            sleep(60)
            continue

        for tunnel in tunnels:
            # select tunnel that forwards to ssh service (tcp/22)
            # FIXME: this loop select the first SSH ngrok tunnel.

            if tunnel["forwards_to"] == "22":
                print("[!] SSH ngrok tunnel found, downloading handshake")

                # extracting to_crack.zip file (wpa_handshake.pcap and RULES.txt) 
                result = get_hash(
                    tunnel['domain'], 
                    tunnel['port'], 
                    config.SSH_USERNAME, 
                    config.HANDSHAKE_LOCATION
                )

                if result:
                    break

        if not result:
            #send_email(f"[X] Error while downloading hash from {config.SSH_USERNAME}@{tunnel['domain']}:{tunnel['port']}:{config.HANDSHAKE_LOCATION}")
            print(f"[X] Error while downloading hash from {config.SSH_USERNAME}@{tunnel['domain']}:{tunnel['port']}:{config.HANDSHAKE_LOCATION}")
            sleep(60)
            continue
        
        print("[!] Hash downloaded successfully...")

        # extracting info from the zip file
        print("[!] Extracting info from the file ./loot/to_crack.zip")
        handshake = extract_files_from_zip("./loot/to_crack.zip")

        if handshake is None:
            #send_email("Invalid files provided in 'to_crack.zip' file")
            print("[X] Invalid files provided...")
            sleep(10)
            continue

        # parse rules from the file RULES.txt        
        print("[!] Parsing Rules...")
        rules = parse_rules(open(handshake['rules'].name, 'r').read())

        if rules is None:
            print("[X] Invalid rules provided...")
            print(open(handshake['rules'].name, 'r').read())
            continue

        if validate_rules(rules) == 1:
            print(f"[X] Wordlist {rules['wordlist']} doesn't exist...")
            continue

        if rules.get('status_check'):
            send_email(f"[!] Crackahash is active...")
            print("[!] Crackahash is active...")
            sleep(60)
            continue            

        # convert wpa_handshake to hashcat format 
        print("[!] Converting wpa_handshake.pcap in a valid hashcat format")
        pcap_to_hashcat(handshake)

        # send email before cracking
        date = datetime.now()
        send_email(f"[!] Start cracking at [{date.year} {date.hour}:{date.minute}.{date.second}]")

        # command to crack
        print("[!] Cracking hash >:)")
        result = run_hashcat(handshake['hashcat'].name, rules['wordlist'])

        # send email after cracking
        date = datetime.now()
        send_email(f"[!] Finish cracking at [{date.year} {date.hour}:{date.minute}.{date.second}]", result)


if __name__ == "__main__":
    try:
        import config
    except:
        print("[!] config.py file is not created...")
        exit(0)

    try:
        main()
    except KeyboardInterrupt:
        print("[!] Program finished by user...")
        exit(0)