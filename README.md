# hibryd-encryption
Uso de algoritmos simétricos y asimétricos para cifrar/descifrar archivos usando Java

# Antes de transferir:
Paso 1: generar una llave  - secretsGenerator.generateAESRandomKey("key.key", 64); //una llave de mayor tamaño tendra problemas al ser descifrada, de tenerlos reduzca la cantidad de bytes
Paso 2: cifrar el archivo base con la llave, usando AES - aesUtils.encryptFile("archivo_origen","archivo_destino");
Paso 3: generar un par de llaves publica y privada - secretsGenerator.generatePublicPrivateKeyPair("destino", 1024);
Paso 4: cifrar la llave AES usando RSA - rsaUtils.encrypt("archivo_origen", "archivo_destino", "llave_publica");
Paso 5: transportarlo de esa manera

# Al recibir
Paso 1: decifrar la llave usando RSA - rsaUtils.decrypt("archivo_origen", "archivo_destino", "llave_privada");
Paso 2: decifrar el archivo con la llave que ha sido descifrada, usando AES
