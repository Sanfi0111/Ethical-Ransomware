### Ransomware:

"Ransomware is a program that affects the computer in various ways. In this case, all we did was encrypt the user's documents (only those located in %userprofile%\Documents). The first step in developing this malware was to understand how the files would be encrypted. The public key used was the same one we used for the development of practice 2. This key was embedded in the code as a variable called llavePublicaRSA. Once having this key, we proceeded to derive a key using specific Python classes that perform this task, for example, the Cryptography class. The PBKDF2-HMAC algorithm was used to encrypt the RSA key into an AES-256 key."

### How to run the Ransomware?

Run it on your own risk, since it will encrypt all of your files in the Documents File. 
Just open the .exe file and Execute.
