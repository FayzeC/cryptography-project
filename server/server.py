# +=======================================================================+
# |                       INTERNAL DOCUMENTATION                          |
# +=======================================================================+                                                    |
# | File Name: server.py                                                  |                                              |
# | Team Members: 1. Rachel Foong                                         |
# |               2. Serene Soo                                           |
# |               3. Faye Chan                                            |
# +=======================================================================+

# +==========================================================================================+
# |                              LIBRARIES AND VARIABLES                                     |
# +==========================================================================================+
# Import Libraries
import datetime, sys, traceback, pickle, json, base64, hashlib, os, getpass, pyotp
from Cryptodome.Cipher import PKCS1_OAEP, PKCS1_v1_5, AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import pkcs1_15 
from Cryptodome.Hash import SHA256
from colorama import Fore, Style, init
init(convert=True)
# Default 
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
server_dict = {}
global rsa_cipher
attempt = 0

# File paths
filePath = "D:\\School\\ACG\\Python\\Assign_Code\\server\\"
default_menu = filePath + "menu_today.txt"

# Key file paths
keyPath = filePath + "keys\\"
server_pubkey_file = keyPath + "rsa_server_public.pem"
server_encrypted_prikey_file = keyPath + "rsa_server_encrypted_private.pem"
client_pubkey_file = keyPath + "rsa_client_public.pem"
hmac_key_file = keyPath + "hmac_secret_key.dat"
otp_key_file = keyPath + "otp_secret_key.dat"

# Result file paths
result_filePath = filePath + "resultfiles\\"
default_save_base = "result-"

# +==========================================================================================+
# |                         MULTIFACTOR AUTHENTICATION(LOGIN AND OTP)                        |
# |                                CODED BY: Rachel and Faye                                 |
# +==========================================================================================+
# Function to load client.json into client dictionary
def load_json():
    global server_dict
    with open(filePath + "server.json") as json_file:
        data = json.load(json_file)

    for user in data['users']:
        username = user
        # Use salt to add additional input to safeguard the password hashes
        ascii_salt_n_key = data['users'][user]['password']
        salt_n_key = base64.b64decode(ascii_salt_n_key.encode('ascii'))
        server_dict[username] = salt_n_key

# Function to write data into client.json when they create a new account
def write_json(username, salt_n_key):
    data = {}
    data['users'] = {}

    ascii_salt_n_key = base64.b64encode(salt_n_key).decode('ascii')
    with open(filePath + "server.json") as json_file: 
        data = json.load(json_file)
        data['users'][username] = {"password": ascii_salt_n_key}

    with open(filePath + "server.json", 'w') as f:
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
        # The key is predetermined and saved into the file to avoid generating different qrcodes everytime a client logins
        # The file is then encrypted with server's public key
        base32secret = getOTPkey()
        # print('Secret:', base32secret) # FOR DEBUGGING
        # Use the secret key to generate OTPs 
        totp = pyotp.TOTP(base32secret)
        # print('OTP code:', totp.now())
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

# Function to decrypt and return server private key 
def decrypt_prikey():
    global rsa_cipher, attempt
    # Only ask for password once
    if attempt == 0:
        while True:
            try:
                password = getpass.getpass(f"\nEnter password to decrypt server private key: ", stream=None)
                server_prikey_content = open(server_encrypted_prikey_file, 'r').read()
                server_prikey = RSA.import_key(server_prikey_content, password)
                attempt += 1
                break
            except ValueError:
                print(f"{Fore.RED}\nIncorrect password!{Style.RESET_ALL}")
        rsa_cipher = PKCS1_OAEP.new(server_prikey)

    # FOR DEBUGGING PURPOSES
    # print("Done importing the private key")
    # print(f"Private Key:\n{server_prikey_content}")
    # print(f"keysize: {server_prikey.size_in_bytes()}")
    print("\nDecrypting the file content with the private key")

    return rsa_cipher

# Function to decrypt and get OTP secret key from otp_secret_key.dat using server private key
def getOTPkey():
    print(f"\nGet OTP key")
    rsa_cipher = decrypt_prikey()

    encrypted=open(otp_key_file, 'rb').read()
    plain_text = rsa_cipher.decrypt(encrypted).decode()
    return plain_text

# Function to prompt server for username and password for login
def login():
    while True:
        print(f"\n-----LOGIN-----")
        try:
            username = input(f"\nUsername: ").lower()
            password = getpass.getpass(f"Password: ", stream=None)

            load_json()
            
            # verify user
            if verify_password(password, server_dict[username]):
                currentUser = username
                print(f"\nHi {Fore.YELLOW}{currentUser}{Style.RESET_ALL}, you have successfully logged in!")
                break
            else:
                print(f"\n{Fore.RED}Incorrect username / password{Style.RESET_ALL}")
        except KeyError:
            print(f"\n{Fore.RED}Incorrect username / password{Style.RESET_ALL}")

# Function to create new server account
def create_account():
    load_json()
    
    while True:
        print(f"-----CREATE ACCOUNT-----")
        username = input(f"\nUsername: ").lower()
        password = getpass.getpass(f"Password: ", stream=None)

        if username == '' or password == '':
            print(f"{Fore.RED}\nInvalid username / password!{Style.RESET_ALL}")
        elif attemptExist(username, server_dict):
            print(f"{Fore.RED}\nSorry, this username exists already.{Style.RESET_ALL}")
        elif password_check(password) != True:
            print(f"{Fore.RED}\nPlease try again{Style.RESET_ALL}")
        else:
            password_cfm = getpass.getpass(f"Confirm password: ", stream=None)
            if password == password_cfm:
                salt_n_key = password_hash(password)
                write_json(username, salt_n_key)
                break
            else:
                print(f"{Fore.RED}\nPasswords do not match!{Style.RESET_ALL}")

# Function to check if new username already exists
def attemptExist(attempt, list):
    if attempt in list:
        return True
    else:
        return False

# Release the following line to create a new server account
# create_account()
login()

# +==========================================================================================+
# |                                SENDING MENU-OF-THE-DAY                                   |
# |                                 HMAC CODED BY: Serene                                    |
# +==========================================================================================+
# Function to decrypt and get hmac key from hmac_secret_key.dat using server private key
def get_hmac_key():
    print("\nGetting HMAC key")
    rsa_cipher = decrypt_prikey()

    encrypted=open(hmac_key_file, 'rb').read()
    plain_text = rsa_cipher.decrypt(encrypted).decode()
    return plain_text

# Function to hash message and send digest and message to client for integrity check
def hmac(conn):
    import hmac, hashlib, time
    # encrypt shared secret key using server public key and store in file
    key = get_hmac_key()
    # print("HMAC key: ", key) # FOR DEBUGGING
    message = open(default_menu, 'r').read()  
    # print("HMAC message: ", message) # FOR DEBUGGING
    encodedkey = str.encode(key)
    # print("encodedkey: ", encodedkey) # FOR DEBUGGING
    hmac1 = hmac.new(encodedkey,message.encode("UTF-8"),hashlib.sha256) # HMAC hash
    digestvalue1 = hmac1.digest()
    # print("Digest value: ",digestvalue1) # FOR DEBUGGING
    # print("Size of the MAC value: ", 8*hmac1.digest_size) # FOR DEBUGGING
    conn.send(digestvalue1)
    conn.send(message.encode("UTF-8"))

# +==========================================================================================+
# |                              RECEIVING DAY-END-INFORMATION                               |
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
        
# Function to decrypt and return day_end information sent by client using server private key and AES key
def rsa_aes_decryption(data):
    print(f"\nRSA AES decryption")
    # print(f"data chunk size; {len(data)}") # FOR DEBUGGING
    rsa_cipher = decrypt_prikey()
    enc_payload = pickle.loads(data)
    if type(enc_payload) != ENC_payload:
        raise runtimeError(f"{Fore.RED}\nInvalid encrypted file{Style.RESET_ALL}")
    aes_key = rsa_cipher.decrypt(enc_payload.enc_session_key) # retreive and decrypt the AES key
    aes_cipher = AES.new(aes_key,AES.MODE_CBC,iv=enc_payload.aes_iv)
    plain_text = unpad(aes_cipher.decrypt(enc_payload.encrypted_content), AES.block_size)
    return plain_text

# Function to verify digital signature after receiving day_end information
def rsa_ds_verify(filename, signature):
    client_pubkey_content = open(client_pubkey_file, 'r').read()
    client_pubkey = RSA.import_key(client_pubkey_content)
    print("\nDone importing the public key") 
    # print(f"Public Key:\n{client_pubkey_content}") # FOR DEBUGGING
    # print(f"keysize: {client_pubkey.size_in_bytes()}") # FOR DEBUGGING

    data_in_bytes = open(result_filePath + filename, 'rb').read()
    digest = SHA256.new(data_in_bytes)
    # FOR DEBUGGING PURPOSES
    # print("\ndigest:")
    # for b in digest.digest():
    #     print("{0:02x}".format(b),end="")
    # print("\nSignature:")
    # for b in signature:
    #     print("{0:02x}".format(b),end="")

    verifier = pkcs1_15.new(client_pubkey)
    try:
        # Release the line below to trigger a invalid signature case
        # digest = SHA256.new("wrongmess".encode())
        verifier.verify(digest, signature)
        print(f"\n{Fore.GREEN}The signature is valid{Style.RESET_ALL}")
    except:
        print(f"\n{Fore.RED}The signature is not valid{Style.RESET_ALL}")
        # delete result file
        print(f"\nDeleting {filename}")
        deleteResultFile = filePath + filename
        os.remove(deleteResultFile)

# Function to receive command from client and carry out functions
def process_connection(conn , ip_addr, MAX_BUFFER_SIZE):
    blk_count = 0
    # receive command / request from client
    net_bytes = conn.recv(MAX_BUFFER_SIZE)
    dest_file = open("temp","w")
    while net_bytes != b'':
        if blk_count == 0: #  1st block
            if cmd_GET_MENU in net_bytes: # ask for menu
                hmac(conn)
                print("\nProcessed SENDING menu")
                return
            elif cmd_END_DAY in net_bytes: # ask for to save end day order
                # receive encrypted data from client
                recvData = conn.recv(MAX_BUFFER_SIZE)
                now = datetime.datetime.now()
                filename = default_save_base +  ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")
                plain_text = rsa_aes_decryption(recvData)
                dest_file = open(result_filePath + filename, 'wb')
                dest_file.write(plain_text)
                blk_count = blk_count + 1
                recvSign = conn.recv(MAX_BUFFER_SIZE)
        else:  # write other blocks
            net_bytes = conn.recv(MAX_BUFFER_SIZE)
    # last block / empty block
    dest_file.close()
    rsa_ds_verify(filename, recvSign)
    print(f"\n{Fore.GREEN}Processed CLOSING done{Style.RESET_ALL}")

def client_thread(conn, ip, port, MAX_BUFFER_SIZE = 4096):
    process_connection(conn, ip, MAX_BUFFER_SIZE)
    conn.close()  # close connection
    print(f'\nConnection ' + ip + ':' + port + " ended\n")

def start_server():
    import socket
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # this is for easy starting/killing the app
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print(r'========================================')
    print(rf'| Socket {Fore.YELLOW}created{Style.RESET_ALL}                       |')
    print
    try:
        soc.bind(("127.0.0.1", 8888))
        print(rf'| Socket {Fore.YELLOW}bind complete{Style.RESET_ALL}                 |')
    except socket.error as msg:
        import sys
        print(f'{Fore.RED}Bind failed. Error :{Style.RESET_ALL}' + str(sys.excinfo()))
        print(r'__')
        print( msg.with_traceback() )
        sys.exit()

    #Start listening on socket
    soc.listen(10)
    print(fr'| Socket {Fore.YELLOW}now listening{Style.RESET_ALL}                 |')
    print(r'========================================')

    # for handling task in separate jobs we need threading
    from threading import Thread

    # this will make an infinite loop needed for
    # not reseting server for every client
    while True:
        conn, addr = soc.accept()
        ip, port = str(addr[0]), str(addr[1])
        print('Accepting connection from ' + ip + ':' + port)
        try:
            Thread(target=client_thread, args=(conn, ip, port)).start()
        except:
            print("Terible error!")
            import traceback
            traceback.print_exc()
    soc.close()

start_server()
