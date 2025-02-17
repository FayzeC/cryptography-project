# encrypting otp secret key using server public key and storing it in a file

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA

filePath = "D:\\School\\ACG\\Python\\Assign_Code\\server\\keys\\"
server_pubkey_file = filePath + "rsa_server_public.pem"
otp_key_file = filePath + "otp_secret_key.dat"

OTPkey = "FNSKM55UKN2MAYFTWVXU7ZUMI63T6FPA"
server_pubkey_content = open(server_pubkey_file, 'r').read()
server_pubkey = RSA.import_key(server_pubkey_content)
rsa_cipher = PKCS1_OAEP.new(server_pubkey)

encrypted = rsa_cipher.encrypt(OTPkey.encode())
out_bytes=open(otp_key_file, 'wb').write(encrypted)
print(f"Total of {out_bytes} bytes written to {otp_key_file}")