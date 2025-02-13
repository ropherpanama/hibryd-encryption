package com.ropherpanama.labs;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Clase de utilidades para cifrar archivos utilizando AES-256
 * 
 * @author ropherpanama
 *
 */
public class AESUtils {

	private SecretKeyAndIv keyAndIv;

	/**
	 * Constructor de la clase AESUtils, debe definir o especificar la llave a
	 * utilizar para los procesos de cifrado y descifrado
	 * 
	 * @param AESkeyFile Archivo que contiene la llave a utilizar
	 * @throws Exception
	 */
	public AESUtils(String AESkeyFile) throws Exception {
		if (AESkeyFile == null || AESkeyFile.isEmpty()) {
			throw new IllegalArgumentException("El archivo de clave AES no puede ser nulo o vacío.");
		}

		byte[] salt = HexUtil.hexStringToByteArray("ED9F90A62A78F01C");

		// Cargar clave desde archivo y derivar clave e IV
		String password = loadKeyFromFile(AESkeyFile);
		keyAndIv = deriveKeyAndIv(password, salt);
	}

	/**
	 * Use este metodo para cifrar un archivo. El archivo se cifrara con la llave
	 * especificada
	 * 
	 * @param inputFile     Archivo origen que sera cifrado
	 * @param encryptedFile Archivo destino que se creara producto del cifrado
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public void encryptFile(String inputFile, String encryptedFile) throws IOException, GeneralSecurityException {

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyAndIv.secretKey, keyAndIv.iv);

		try (FileInputStream fileInputStream = new FileInputStream(inputFile);
				FileOutputStream fileOutputStream = new FileOutputStream(encryptedFile);
				CipherOutputStream cipherOutputStream = new CipherOutputStream(fileOutputStream, cipher)) {

			byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = fileInputStream.read(buffer)) != -1) {
				cipherOutputStream.write(buffer, 0, bytesRead);
			}
		}
		System.out.println("Archivo cifrado correctamente, almacenado en : " + encryptedFile);
	}

	/**
	 * Use este metodo para descifrar un archivo cifrado con AES-256, se debe usar
	 * la misma llave que fue usada para cifrar el archivo original
	 * 
	 * @param encryptedFile Archivo origen (cifrado) que sera descifrado
	 * @param decryptedFile Archivo destino producto del proceso de descifrado
	 * @throws Exception
	 */
	public void decryptFile(String encryptedFile, String decryptedFile) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, keyAndIv.secretKey, keyAndIv.iv);

		try (FileInputStream fileInputStream = new FileInputStream(encryptedFile);
				FileOutputStream fileOutputStream = new FileOutputStream(decryptedFile)) {

			byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = fileInputStream.read(buffer)) != -1) {
				byte[] decryptedBytes = cipher.update(buffer, 0, bytesRead);
				if (decryptedBytes != null) {
					fileOutputStream.write(decryptedBytes);
				}
			}

			byte[] finalBytes = cipher.doFinal();
			if (finalBytes != null) {
				fileOutputStream.write(finalBytes);
			}
		}

		System.out.println("Archivo descifrado correctamente, almacenado en : " + decryptedFile);
	}

	private static String loadKeyFromFile(String keyFilePath) throws IOException {
		return Files.readString(Paths.get(keyFilePath)).trim();
	}

	private static SecretKeyAndIv deriveKeyAndIv(String password, byte[] salt) throws Exception {
		int iterations = 10000;
		int keyLength = 256; // AES-256 requiere una clave de 256 bits (32 bytes)
		int ivLength = 128; // AES usa un IV de 128 bits (16 bytes)

		// Deriva la clave usando PBKDF2
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength + ivLength);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		byte[] keyAndIv = factory.generateSecret(spec).getEncoded();

		// La clave está en los primeros 32 bytes, el IV en los siguientes 16 bytes
		byte[] key = new byte[32];
		byte[] iv = new byte[16];
		System.arraycopy(keyAndIv, 0, key, 0, 32);
		System.arraycopy(keyAndIv, 32, iv, 0, 16);

		return new SecretKeyAndIv(new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
	}

	public static class SecretKeyAndIv {
		public SecretKey secretKey;
		public IvParameterSpec iv;

		public SecretKeyAndIv(SecretKey secretKey, IvParameterSpec iv) {
			this.secretKey = secretKey;
			this.iv = iv;
		}
	}

	// Clase para convertir de hexadecimal a byte[]
	public static class HexUtil {
		public static byte[] hexStringToByteArray(String hex) {
			int length = hex.length();
			byte[] data = new byte[length / 2];
			for (int i = 0; i < length; i += 2) {
				data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
						+ Character.digit(hex.charAt(i + 1), 16));
			}
			return data;
		}
	}

	public static void main(String[] args) {
		try {
			// ENCRYPT
			AESUtils aesUtils = new AESUtils("encrypt-file/key.key");
			aesUtils.encryptFile("encrypt-file/MOCK_DATA.csv", "encrypt-file/encripted_file.enc");

			// DECRYPT, USA LA LLAVE DESCIFRADA
			AESUtils aesUtils2 = new AESUtils("encrypt-file/keyAES.dec");
			aesUtils2.decryptFile("encrypt-file/encripted_file.enc", "encrypt-file/decripted_file.dec");
		} catch (Exception e) {
			System.out.println("Error al realizar el proceso de cifrado/descifrado de archivo.");
			e.printStackTrace();
		}
	}
}
