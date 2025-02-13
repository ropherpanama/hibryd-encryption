# hibryd-encryption
Uso de algoritmos simétricos y asimétricos para cifrar/descifrar archivos usando Java

# Antes de transferir:

1. **Generar una llave**  - secretsGenerator.generateAESRandomKey("key.key", 64); //una llave de mayor tamaño tendra problemas al ser descifrada, de tenerlos reduzca la cantidad de bytes
2. **Cifrar el archivo base** con la llave, usando AES - aesUtils.encryptFile("archivo_origen","archivo_destino");
3. **Generar un par de llaves publica y privada** - secretsGenerator.generatePublicPrivateKeyPair("destino", 1024);
4. **Cifrar la llave AES usando RSA** - rsaUtils.encrypt("archivo_origen", "archivo_destino", "llave_publica");
5. **Transportarlo de esa manera**

# Al recibir
1. **Descifrar la llave usando RSA** - rsaUtils.decrypt("archivo_origen", "archivo_destino", "llave_privada");
2. **Descifrar el archivo** con la llave que ha sido descifrada, usando AES
