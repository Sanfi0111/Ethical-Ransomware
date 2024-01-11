### Ransomware:
El ransomware es un programa que afecta a la computadora de distintas formas. En este caso, lo único que realizamos fue encriptar los documentos del usuario (sólo aquellos que se encuentren en %userprofile%\Documents).
Lo primero que se realizó en el desarrollo de este malware, fue entender cómo se iban a cifrar los archivos. 
La llave pública que se ocupó, fue la misma que ocupamos para el desarrollo de la práctica 2. Esta se dejó dentro del código como una variable, llamada _llavePublicaRSA_ 
Una vez teniendo esta llave, procedimos a derivar una llave ocupando clases específicas de python que realizan esta tarea, por ejemplo, la clase **Cryptography**. Se ocupó el algoritmo  PBKDF2-HMAC para cifrar la llave RSA en una llave EAS-256. 
