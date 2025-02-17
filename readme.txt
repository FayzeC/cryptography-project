** Please change the filePath on all the python files and download Google Authenticator and pip install pyotp in vscode terminal!

--------------------
|  KEY MANAGEMENT  |
--------------------
AES session key is generated every time the day-closing information is sent
Password used to encrypt both server and client RSA private keys: @CGcode88

SERVER KEYS:
RSA keypair is generated using gen_server_rsa.py, and stored in rsa_server_public.pem and rsa_server_encrypted_private.pem
HMAC secret key is encrypted and stored in hmac_secret_key.dat using store_server_hmac_key.py
OTP secret key is predetermined, encrypted and stored in otp_secret_key.dat using store_server_otp_key.py

CLIENT KEYS:
RSA keypair is generated using gen_client_rsa.py, and stored in rsa_client_public.pem and rsa_client_encrypted_private.pem
HMAC secret key is encrypted and stored in hmac_secret_key.dat using store_client_hmac_key.py
OTP secret key is predetermined, encrypted and stored in otp_secret_key.dat using store_client_otp_key.py

-----------
|  LOGIN  |
-----------
-- current usernames and passwords --
[server]
username: server
password: @CGcode0
[client]
username: client1
password: @CGcode1
username: client2
password @CGcode2

---------
|  OTP  |
---------
Install pyotp (pip install pyotp)
Please download Google Authenticator from App Store or Google Play to get the OTP for multifactor authentication
Paste the following link in google to view the QR code and scan it using Google Authenticator:
https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Secure%20App:acg%40google.com?secret=FNSKM55UKN2MAYFTWVXU7ZUMI63T6FPA&issuer=Secure%20App
A new OTP will be generated every 30 seconds
It is assumed that the QRcode or link will be given to clients physically to prevent attackers from getting the OTPs when they infiltrate the system

----------
|  HMAC  |
----------
HMAC secret key is read from hmac_secret_key.dat and decrypted on both client and server

----------------------------------------------------------
|  RSA + AES cryptography (for day-closing information)  |
----------------------------------------------------------
RSA keys are imported by reading from the .pem files
Password used to encrypt both server and client RSA private keys: @CGcode88
AES session key is used to encrypt and decrypt day-closing information
Server RSA public key is used to encrypt AES session key (on client)
Server RSA private key is used to decrypt AES session key (on server)

---------------------------------
|  Digital signature using RSA  |
---------------------------------
Client RSA private key is used to sign the day-closing information
Client RSA public key is used to verify the day-closing information