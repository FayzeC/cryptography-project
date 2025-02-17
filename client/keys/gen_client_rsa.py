#!/usr/bin/env python3
#ST2504 - ACG Practical - myRsaKeysToFiles.py
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
import getpass
# Generate a RSA key pair.
# Store the private key and public key to two seperate files. 
# main program starts here
filePath = "C:\\ACG_code\\Assign_Code\\client\\keys\\"
serverPath = "C:\\ACG_code\\Assign_Code\\server\\keys\\"
client_prikey_file = filePath + "rsa_client_private.pem"
client_encrypted_prikey_file = filePath + "rsa_client_encrypted_private.pem"

print("Generating an RSA key pair...")
# Generate a 1024-bit or 2024-bit long RSA Key pair.
keypair=RSA.generate(2048)

# store the public key to public.pem (client + server)
with open(filePath + "rsa_client_public.pem","w") as f:
    print(keypair.publickey().exportKey().decode() ,file=f)
f.close()
with open(serverPath + "rsa_client_public.pem","w") as f:
    print(keypair.publickey().exportKey().decode() ,file=f)
f.close()
print("Public Key stored on to  'public.pem'")


# encrypting and storing rsa private key
from cryptography.hazmat.primitives import serialization
client_prikey = serialization.load_pem_private_key(keypair.exportKey(), None)

def password_check(passwd):
    valid = True
    specialSymbols = ['!', '@', '#', '$', '%']

    if len(passwd) < 8:
        print(f"Length of password should be at least 8 characters")
        valid = False

    if len(passwd) > 10:
        print(f"Length of password should not be greater than 10 characters")
        valid = False

    if not any(char.isdigit() for char in passwd): 
        print('Password should have at least one numeral') 
        valid = False
    
    if not any(char.isupper() for char in passwd): 
        print('Password should have at least one uppercase letter') 
        valid = False
        
    if not any(char.islower() for char in passwd): 
        print('Password should have at least one lowercase letter') 
        valid = False
    
    if not any(char in specialSymbols for char in passwd): 
        print('Password should have at least one of the symbols !@#$%') 
        valid = False
    
    if valid:
        return valid

def get_passwd():
    while True:
        password = getpass.getpass(f"\nEnter password to encrypt private.pem: ", stream=None)

        if password_check(password) != True:
            print(f"Please try again")
        else:
            password_cfm = getpass.getpass(f"Confirm password: ", stream=None)
            if password == password_cfm:
                break
            else:
                print(f"Passwords do not match!")
    return password

# get password to encrypt private key
password = get_passwd()
pem = client_prikey.private_bytes(
encoding=serialization.Encoding.PEM,
format=serialization.PrivateFormat.PKCS8,
encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
)

with open(client_encrypted_prikey_file, 'w') as f:
    print(pem.decode(), file=f)
f.close()