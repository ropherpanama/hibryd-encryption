from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

# Ruta de archivos
rsa_private_key_file = "private.pem"
encrypted_aes_key_file = "aes_key.key.enc"
encrypted_file = "MOCK_DATA.enc"
output_file = "archivo_descifrado.txt"  # Usamos .txt porque es un archivo de texto

# 1. Descifrar clave AES con RSA
def decrypt_aes_key():
    # Leer la clave privada RSA
    with open(rsa_private_key_file, "rb") as key_file:
        private_key = RSA.import_key(key_file.read())

    # Leer la clave AES cifrada en formato Base64
    with open(encrypted_aes_key_file, "rb") as enc_key_file:
        encrypted_aes_key = enc_key_file.read()

    # Descifrar la clave AES usando RSA con OAEP
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Decodificar la clave AES de base64
    aes_key = base64.b64decode(aes_key)

    # Verificar que la clave AES tiene el tamaño correcto
    if len(aes_key) != 32:
        raise ValueError(f"Error: La clave AES no tiene el tamaño correcto ({len(aes_key)} bytes)")

    print(f"Clave AES descifrada correctamente ({len(aes_key)} bytes).")
    return aes_key

# 2. Descifrar el archivo usando la clave AES
def decrypt_file(aes_key):
    with open(encrypted_file, "rb") as enc_file:
        iv = enc_file.read(16)  # Leer los primeros 16 bytes como el IV
        encrypted_data = enc_file.read()

    # Verificar que los datos se leyeron correctamente
    print(f"IV leído: {iv.hex()}")
    print(f"Datos cifrados leídos: {encrypted_data.hex()}")

    # Desencriptar usando AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = cipher_aes.decrypt(encrypted_data)
    print(f"Datos descifrados: {decrypted_data.hex()}")

    # Eliminar padding PKCS#7
    padding_length = decrypted_data[-1]
    print(f"Padding length: {padding_length}")
    decrypted_data = decrypted_data[:-padding_length]

    # Verificar los datos después de eliminar el padding
    print(f"Datos después de eliminar el padding: {decrypted_data.decode('utf-8', 'ignore')}")

    # Guardar el archivo descifrado como texto
    with open(output_file, "wb") as out_file:  # Usamos "wb" para guardar el archivo en binario, pero es texto
        out_file.write(decrypted_data)

    print(f"Archivo descifrado correctamente en: {output_file}")

# 3. Ejecución
try:
    aes_key = decrypt_aes_key()  # Paso 1: Descifrar la clave AES
    decrypt_file(aes_key)        # Paso 2: Descifrar el archivo
except Exception as e:
    print(f"Error durante el descifrado: {e}")
