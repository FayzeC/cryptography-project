# encrypting hmac secret key using client public key and storing it in a file

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA


filePath = "C:\\ACG_code\\Assign_Code\\client\\keys\\"
client_pubkey_file = filePath + "rsa_client_public.pem"
hmac_key_file = filePath + "hmac_secret_key.dat"

# key =  "this is the key for HMAC"  # shared secret key
key = "HMAC key"
client_pubkey_content = open(client_pubkey_file, 'r').read()
client_pubkey = RSA.import_key(client_pubkey_content)
rsa_cipher = PKCS1_OAEP.new(client_pubkey)
# print(f"Done importing the public key") 
# print(f"Public Key:\n{server_pubkey_content}") 
# print(f"keysize: {server_pubkey.size_in_bytes()}")
# print(f"Encrypting the file content with the public key")

encrypted = rsa_cipher.encrypt(key.encode())
out_bytes=open(hmac_key_file, 'wb').write(encrypted)
print(f"Total of {out_bytes} bytes written to {hmac_key_file}")