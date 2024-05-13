# Crackahash
## Description
Is your laptop a piece of shi*ty tile that can't crack a simple hash without it taking you until you're the same age as your grandmother? But your desktop machine is a NASA computer that can crack hashes faster than quantum computers? Well, if that is the case, then this tool is what you needed. Crackahash is a tool written in python that let you crack hashes from your desktop machine. Simply start a SSH service and an ngrok tunnel in your laptop from anywhere and crackahash will connect and download the juicy hash from your laptop using ngrok API, after that, it will start hashcat optimized to use your GPU to crack the hash and if succeed, it will send the password to your email. 

## Installation
### 1. ngrok installation and configuration [Despktop and Laptop]
Install ngrok in your laptop and your desktop machine via Apt with the following commands:
```bash
# add ngrok keyring to trusted gpg keys
curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null

# add ngrok source to apt source directory
echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list 

# update packages and install ngrok
sudo apt update && sudo apt install ngrok
```
Run the following command to add your authtoken to the default ngrok.yml configuration file.
```bash
# you should get your authtoken from your ngrok account
# visit https://dashboard.ngrok.com/get-started/setup/linux
ngrok config add-authtoken <token>
```
It is important to get an API KEY from ngrok. To do so, you have to generate one visiting this site: 
- https://dashboard.ngrok.com/api

Here you should click in the **New API Key** button and copy/paste the API Key inside the `config.py` file in the `NGROK_API_KEY` variable.

### 2. openssh-server installation and configuration [Laptop]
Install openssh-server in your laptop with the following commands:
```bash
# install openssh-server
sudo apt install openssh-server 

# generate ssh keys
ssh-keygen  # just press enter
```
You should generate ssh-keys in your desktop machine also. When you're done generating your desktop machine ssh keys. Then you have to add the public keys from your desktop machine to your laptop authorized keys with the following commands: (your laptop and desktop machine must be on the same network)
```bash
### EXECUTE IN THE LAPTOP
# get your laptop ip address and save it
ifconfig
...

# start a listener in your laptop
nc -lvnp 6969 >> ~/.ssh/authorized_keys

### EXECUTE IN THE DESKTOP
cat ~/.ssh/id_rsa.pub | nc <laptop_ip_address> 6969 
PRESS CTRL + C
```
### 3. Install the required programs. [Desktop]
Crackahash requires the following programs:
- scp: tool to transfer files from your laptop to your desktop machine securely.
- crunch: used to generate wordlists.
- hashcat: program used to crack hashes. 
- hashcat-nvidia: utilities for hashcat to use a nvidia GPU. 
- hcxtools: tools to manipulate pcap files.

You can install the programs with the following command:
```bash
$ sudo apt install scp crunch hashcat hashcat-nvidia hcxtools
```

## Usage
### Desktop Usage
From your desktop machine, you only have to set up the `config.py` file inside the same directory as the `crackahash.py` script. This is an example of a `config.py` file.
```python
# NGROK CONFIGURATION
NGROK_API_KEY = "<NGROK API KEY HERE>"

# SSH CONFIGURATION
SSH_USERNAME = "<SSH OF THE USERNAME OF THE LAPTOP TO LOGIN>"

# LOCATION WHERE HANDSHAKES ARE STORED IN YOUR LAPTOP
HANDSHAKE_LOCATION = "~/HANDSHAKES/to_crack.zip"

# LOCATION WHERE WORDLIST ARE STORED IN YOUR DESKTOP MACHINE
WORDLISTS_LOCATION = "/usr/share/wordlists/"

# EMAIL CONFIGURATION
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT   = 465  # 465 for SSL
SMTP_USER   = "youremail@gmail.com"
SMTP_PASS   = "<your google app password>"
```
Now you can execute `crackahash.py` which will check for active ngrok tunnels every minute.
```
$ python3 crackahash.py
[!] Getting active ngrok tunnels
[X] No tunnels open, waiting until the next retry...
[!] Getting active ngrok tunnels
[X] No tunnels open, waiting until the next retry...
```

## Laptop usage
From your laptop, create a directory as indicated in the `config.py` file in the `HANDSHAKE_LOCATION` variable. For example, in my `config.py` file, i have `HANDSHAKE_LOCATION="~/HANDSHAKES/to_crack.zip` so i need to  create a directory in my home folder called `HANDSHAKES`. 
```bash
# creating directory
$ mkdir ~/HANDSHAKES

# changing directory to ~/HANDSHAKES
$ cd ~/HANDSHAKES
```
Now you have to create a zip file called as indicated in the config.py file in the `HANDSHAKE_LOCATION` variable. This zip file must contain the pcap file called `wpa_handshake.pcap` and a plain text file called `RULES.txt`. (`RULES.TXT` is required)
```bash
# HANDSHAKE_LOCATION = "~/HANDSHAKES/to_crack.zip"
$ zip to_crack.zip wpa_handshake.pcap RULES.txt

$ unzip -l to_crack.zip
Archive:  /home/<your user>/HANDSHAKES/to_crack.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       41  2024-05-08 20:47   RULES.txt
      971  2024-05-08 17:14   wpa_handshake.pcap
---------                     -------
     1012                     2 files

```
The file `RULES.txt` should contain rules used by the `crackahash.py` program. The available rules are:
```
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
```
When a wordlist is specified, `crackahash.py` will search the wordlist in the path specified by the `WORDLISTS_LOCATION` variable in the `config.py` file.
For example, if the `WORDLISTS_LOCATION="/usr/share/wordlists/"` then, when we specify `WORDLIST="rockyou.txt"`, the program will check if the file `/usr/share/wordlists/rockyou.txt` file exists. If it doesn't exist, then the program will execute the crunch rule to create a wordlist in the specified worlists path.
