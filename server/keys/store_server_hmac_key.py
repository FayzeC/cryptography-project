# encrypting hmac secret key using server public key and storing it in a file

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA


filePath = "C:\\ACG_code\\Assign_Code\\server\\keys\\"
server_pubkey_file = filePath + "rsa_server_public.pem"
hmac_key_file = filePath + "hmac_secret_key.dat"

# key =  "this is the key for HMAC"  # shared secret key
key = "HMAC key"
server_pubkey_content = open(server_pubkey_file, 'r').read()
server_pubkey = RSA.import_key(server_pubkey_content)
rsa_cipher = PKCS1_OAEP.new(server_pubkey)
# print(f"Done importing the public key") 
# print(f"Public Key:\n{server_pubkey_content}") 
# print(f"keysize: {server_pubkey.size_in_bytes()}")
# print(f"Encrypting the file content with the public key")

encrypted = rsa_cipher.encrypt(key.encode())
out_bytes=open(hmac_key_file, 'wb').write(encrypted)
print(f"Total of {out_bytes} bytes written to {hmac_key_file}")