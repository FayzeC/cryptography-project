#!/usr/bin/env python3
# +=======================================================================+
# |                       INTERNAL DOCUMENTATION                          |
# +=======================================================================+
# | File Name: client.py                                                  |                                             |
# | Team Members: 1. Rachel Foong                                         |
# |               2. Serene Soo                                           |
# |               3. Faye Chan                                            |
# +=======================================================================+

# +==========================================================================================+
# |                              LIBRARIES AND VARIABLES                                     |
# +==========================================================================================+
# Import Libraries
import socket, pickle, time, getpass, hashlib, json, os, base64, hmac, pyotp
from Cryptodome.Cipher import PKCS1_OAEP, AES  
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15 
from Cryptodome.Hash import SHA256
from colorama import Fore, Style, init
init(convert=True)
# Default 
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 8888        # The port used by the server
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
client_dict = {}
global client_prikey
attempt = 0

# File paths
filePath = "D:\\School\\ACG\\Python\\Assign_Code\\client\\"
menu_file = filePath + "menu.csv"
return_file = filePath + "day_end.csv"
encrypted_data_file = filePath + "encrypted.dat"

# Key file paths
keyPath = filePath + "keys\\"
server_pubkey_file = keyPath + "rsa_server_public.pem"
client_pubkey_file = keyPath + "rsa_client_public.pem"
client_encrypted_prikey_file = keyPath + "rsa_client_encrypted_private.pem"
hmac_key_file = keyPath + "hmac_secret_key.dat"
otp_key_file = keyPath + "otp_secret_key.dat"

# +==========================================================================================+
# |                         MULTIFACTOR AUTHENTICATION(LOGIN AND OTP)                        |
# |                                CODED BY: Rachel and Faye                                 |
# +==========================================================================================+
# Function to load client.json into client dictionary
def load_json():
    global client_dict
    with open(filePath + "client.json") as json_file:
        data = json.load(json_file)

    for user in data['users']:
        username = user
        # Use salt to add additional input to safeguard the password hashes
        ascii_salt_n_key = data['users'][user]['password']
        salt_n_key = base64.b64decode(ascii_salt_n_key.encode('ascii'))
        client_dict[username] = salt_n_key

# Function to write data into client.json when they create a new account
def write_json(username, salt_n_key):
    data = {}
    data['users'] = {}

    ascii_salt_n_key = base64.b64encode(salt_n_key).decode('ascii')
    with open(filePath + "client.json") as json_file: 
        data = json.load(json_file)
        data['users'][username] = {"password": ascii_salt_n_key}

    with open(filePath + "client.json", 'w') as f:
        json.dump(data, f, indent=4)

# Function to validate password complexity when a new account is created
def password_check(passwd):
    valid = True
    specialSymbols = ['!', '@', '#', '$', '%']

    if len(passwd) < 8:
        print(f"{Fore.RED}\nLength of password should be at least 8 characters{Style.RESET_ALL}")
        valid = False

    if len(passwd) > 10:
        print(f"{Fore.RED}\nLength of password should not be greater than 10 characters{Style.RESET_ALL}")
        valid = False

    if not any(char.isdigit() for char in passwd): 
        print(f'{Fore.RED}\nPassword should have at least one numeral{Style.RESET_ALL}') 
        valid = False
    
    if not any(char.isupper() for char in passwd): 
        print(f'{Fore.RED}\nPassword should have at least one uppercase letter{Style.RESET_ALL}') 
        valid = False
        
    if not any(char.islower() for char in passwd): 
        print(f'{Fore.RED}\nPassword should have at least one lowercase letter{Style.RESET_ALL}') 
        valid = False
    
    if not any(char in specialSymbols for char in passwd): 
        print(f'{Fore.RED}\nPassword should have at least one of the symbols !@#$%{Style.RESET_ALL}') 
        valid = False
    
    if valid:
        return valid

# Function to hash passwords
def password_hash(password):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        'sha512', # hash digest algorithm for HMAC
        password.encode('utf-8'), # convert the password to bytes
        salt, # provide the salt
        100000 # it is recommended to use at least 100,000 iterations of SHA-256
        )

    # to store in json file
    storage = salt + key
    return storage

# Function to verify password and OTP
def verify_password(password, stored):
    salt_from_stored = stored[:32] # 32 is the length of the salt
    key_from_stored = stored[32:]

    new_key = hashlib.pbkdf2_hmac(
        'sha512',
        password.encode('utf-8'), # convert the password to bytes
        salt_from_stored,
        100000
    )

    if new_key == key_from_stored:
        print(f"{Fore.GREEN}\nPassword is correct{Style.RESET_ALL}")
        # After client has passed the login, they will be asked to enter an OTP to form multifactor authentication(2FA)
        # A secret key can be generated with the following code:
        # base32secret = pyotp.random_base32()
        # The key is predetermined and saved into the file(otp_secret_key.dat) to avoid generating different qrcodes everytime a client logins
        # The file is then encrypted with client's public key
        base32secret = getOTPkey()
        # print('Secret:', base32secret) # FOR DEBUGGING
        # Use the secret key to generate OTPs 
        totp = pyotp.TOTP(base32secret)
        # print('OTP code:', totp.now()) # DEBUGGING
        while True:
            try: 
                verifyOTP = int(input("\nEnter OTP: "))
                if totp.verify(verifyOTP):
                    print(f"{Fore.GREEN}\nOTP is valid{Style.RESET_ALL}")
                    return True
                else:
                    print(f"{Fore.RED}\nInvalid OTP!{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}\nPlease enter a number!{Style.RESET_ALL}")
        return True
    else:
        print(f"{Fore.RED}\nPassword is incorrect{Style.RESET_ALL}")
        return False

# Function to decrypt and return client private key 
def decrypt_prikey():
    global client_prikey, attempt
    # Only ask for password once
    if attempt == 0:
        while True:
            try:
                password = getpass.getpass(f"\nEnter password to decrypt client private key: ", stream=None)
                client_prikey_content = open(client_encrypted_prikey_file, 'r').read()
                client_prikey = RSA.import_key(client_prikey_content, password)
                attempt += 1
                break
            except ValueError:
                print(f"{Fore.RED}\nIncorrect password!{Style.RESET_ALL}")

    # FOR DEBUGGING PURPOSES
    # print("Done importing the private key") 
    # print(f"Private Key:\n{client_prikey_content}") 
    # print(f"keysize: {client_prikey.size_in_bytes()}")

    return client_prikey

# Function to decrypt and get OTP secret key from otp_secret_key.dat using client private key
def getOTPkey():
    print(f"\nGetting OTP key")
    client_prikey = decrypt_prikey()
    rsa_cipher = PKCS1_OAEP.new(client_prikey)

    print("\nDecrypting the file content with the private key")
    encrypted=open(otp_key_file, 'rb').read()
    plain_text = rsa_cipher.decrypt(encrypted).decode()
    return plain_text

# Function to proompt client for username and password for login
def login():
    while True:
        print(f"\n-----LOGIN-----")
        try:
            username = input(f"\nUsername: ").lower()
            password = getpass.getpass(f"Password: ", stream=None)

            load_json()
            
            # verify user
            if verify_password(password, client_dict[username]):
                currentUser = username
                print(f"\nHi {Fore.YELLOW}{currentUser}{Style.RESET_ALL}, you have successfully logged in!")
                break
            else:
                print(f"\n{Fore.RED}Incorrect username / password{Style.RESET_ALL}")
        except KeyError:
            print(f"\n{Fore.RED}Incorrect username / password{Style.RESET_ALL}")

# Function to create new client account
def create_account():
    load_json()
    
    while True:
        print(f"\n-----CREATE ACCOUNT-----")
        username = input(f"\nUsername: ").lower()
        password = getpass.getpass(f"Password: ", stream=None)

        if username == '' or password == '':
            print(f"\n{Fore.RED}Invalid username / password!{Style.RESET_ALL}")
        elif attemptExist(username, client_dict):
            print(f"\n{Fore.RED}Sorry, this username exists already.{Style.RESET_ALL}")
        elif password_check(password) != True:
            print(f"\n{Fore.RED}Please try again{Style.RESET_ALL}")
        else:
            password_cfm = getpass.getpass(f"Confirm password: ", stream=None)
            if password == password_cfm:
                salt_n_key = password_hash(password)
                write_json(username, salt_n_key)
                break
            else:
                print(f"\n{Fore.RED}Passwords do not match!{Style.RESET_ALL}")

# Function to check if new username already exists
def attemptExist(attempt, list):
    if attempt in list:
        return True
    else:
        return False

# Release the following line to create a new client account
# create_account()
login()

# +==========================================================================================+
# |                              RECEIVING MENU-OF-THE-DAY                                   |
# |                                 HMAC CODED BY: Serene                                    |
# +==========================================================================================+
# Function to decrypt and return hmac key from hmac_secret_key.dat using client's private key
def get_hmac_key():
    print(f"\nGetting HMAC key")
    client_prikey = decrypt_prikey()
    rsa_cipher = PKCS1_OAEP.new(client_prikey)

    print("\nDecrypting the file content with the private key")
    encrypted=open(hmac_key_file, 'rb').read()
    plain_text = rsa_cipher.decrypt(encrypted).decode()
    return plain_text

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((HOST, PORT))
    my_socket.sendall(cmd_GET_MENU)
    # Validate the intergrity of message using HMAC
    key = get_hmac_key()
    # print(f"HMAC key: ", key) # FOR DEBUGGING
    encodedkey = str.encode(key)
    digestvalue1 = my_socket.recv(4096)
    message = my_socket.recv(4096)
    message = message.decode("UTF-8")
    # print("HMAC message: ", message) # FOR DEBUGGING
    Clienthmac1 = hmac.new(encodedkey,message.encode("UTF-8"),hashlib.sha256)
    Clientdigestvalue1 = Clienthmac1.digest()
    # print("Digest value: ",Clientdigestvalue1) # FOR DEBUGGING
    # print("Size of the MAC value: ", 8*Clienthmac1.digest_size) # FOR DEBUGGING
    # Write data into menu_file if hashes match
    if digestvalue1 == Clientdigestvalue1:
        print("\nNo problems, digest is the same.")
        menu_file = open(menu_file,"w")
        menu_file.write(message)
        menu_file.close()
print(f"\nReceived\n{message}")
my_socket.close()

# +==========================================================================================+
# |                              SENDING DAY-END-INFORMATION                                 |
# |                        RSAAESEncryption CODED BY: Rachel & Serene                        |
# |                        DIGITAL SIGNATURE CODED BY: Rachel & Faye                         |        
# +==========================================================================================+
class ENC_payload:
    # A data class to store a encrypted file content.
    # The file content has been encrypted using an AES key.
    # The AES key is encrypted by a public key and stored in the enc_session_key instance attribute. 
    def __init__(self):
        self.enc_session_key=""
        self.aes_iv = ""
        self.encrypted_content=""

# Function to encrypt day_end.csv using AES key and use RSA to encrypt the AES key then write encrypted data, key and IV into encrypted.dat
def rsa_aes_encryption():
    server_pubkey_content = open(server_pubkey_file, 'r').read()
    server_pubkey = RSA.import_key(server_pubkey_content)
    rsa_cipher = PKCS1_OAEP.new(server_pubkey)
    print(f"\nDone importing the public key") 
    # print(f"Public Key:\n{server_pubkey_content}") # FOR DEBUGGING
    # print(f"keysize: {server_pubkey.size_in_bytes()}") # FOR DEBUGGING
    print(f"\nEncrypting the file content with the public key")

    keysize = 16  # 16 bytes -> 128 bits, 32 bytes -> 256 bits
    data_in_bytes = open(return_file, 'rb').read(1024)
    # print(f"data chunk size: {len(data_in_bytes)}") # FOR DEBUGGING
    print(f"\nGenerating a {keysize*8}-bits AES key...")
    aes_key = get_random_bytes(keysize) # generate random bytes array
    print(f"\nThe AES key is generated.")
    
    aes_cipher = AES.new(aes_key,AES.MODE_CBC)
    ciphertext = aes_cipher.encrypt(pad(data_in_bytes, AES.block_size))
    enc_payload = ENC_payload()
    enc_payload.enc_session_key = rsa_cipher.encrypt(aes_key) 
    enc_payload.aes_iv = aes_cipher.iv # retrieve the randomly generated iv value 
    enc_payload.encrypted_content = ciphertext
    encrypted = pickle.dumps(enc_payload) # serialize the enc_payload object into a byte stream.
    
    out_bytes = open(encrypted_data_file, 'wb').write(encrypted)
    print(f"\nTotal of {out_bytes} bytes written to encrypted.dat")

# Function to sign the day_end.csv with client private key and returns signature
def rsa_ds_sign():
    client_prikey = decrypt_prikey()
    print(f"\nSigning the sha256 digest of the phrase with the private key of the RSA key pair")

    data_in_bytes = open(return_file, 'rb').read(1024)
    digest = SHA256.new(data_in_bytes)
    # FOR DEBUGGING PURPOSES
    # print(f"\ndigest:")
    # for b in digest.digest():
    #     print("{0:02x}".format(b),end="")

    signer = pkcs1_15.new(client_prikey)
    signature = signer.sign(digest)
    # print(f"\nSignature:")
    # for b in signature:
    #     print("{0:02x}".format(b),end="")
    # print(f"")

    return signature

rsa_aes_encryption()
signature = rsa_ds_sign()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((HOST, PORT))
    # Send command
    my_socket.sendall(cmd_END_DAY)
    out_file = open(encrypted_data_file, 'rb')
    file_bytes = out_file.read(1024)
    # Send encrypted data (rsaaes)
    while file_bytes != b'':
        my_socket.send(file_bytes)
        file_bytes = out_file.read(1024) # read next block from file
    out_file.close()
    # Send digital signature
    my_socket.send(signature)
    my_socket.close()
my_socket.close()