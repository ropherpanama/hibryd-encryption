package com.ropherpanama.labs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * Clase de utilidades para cifrar archivos utilizando RSA
 * 
 * @author ropherpanama
 *
 */
public class RSAUtils {

	private static PublicKey getPublicKey(String publicKeyFile) throws IOException, GeneralSecurityException {
		byte[] keyBytes = Files.readAllBytes(Paths.get(publicKeyFile));
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(keySpec);
	}

	private static PrivateKey getPrivateKey(String privateKeyFile) throws IOException, GeneralSecurityException {
		byte[] keyBytes = Files.readAllBytes(Paths.get(privateKeyFile));
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(keySpec);
	}

	/**
	 * Use este metodo para cifrar un archivo. El archivo se cifrara con la llave
	 * publica especificada
	 * 
	 * @param inputFile     Archivo que sera cifrado
	 * @param outputFile    Archivo que se generara como resultado del proceso de
	 *                      cifrado
	 * @param publicKeyFile Archivo que contiene la llave publica
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public void encrypt(String inputFile, String outputFile, String publicKeyFile)
			throws IOException, GeneralSecurityException {
		// Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKeyFile));
		byte[] encryptedData = cipher.doFinal(inputFile.getBytes());

		Files.write(Paths.get(outputFile), encryptedData);
		System.out.println("Archivo cifrado correctamente, almacenado en : " + outputFile);
	}

	/**
	 * Use este metodo para descifrar un archivo. El archivo sera descifrado con la
	 * llave privada especificada.
	 * 
	 * @param inputFile      Archivo cifrado
	 * @param outputFile     Archivo que se generara producto del proceso de
	 *                       descifrado
	 * @param privateKeyFile Archivo que contiene la llave privada
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public void decrypt(String inputFile, String outputFile, String privateKeyFile)
			throws IOException, GeneralSecurityException {
		byte[] encryptedData = Files.readAllBytes(Paths.get(inputFile));
		// Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKeyFile));
		byte[] decryptedData = cipher.doFinal(encryptedData);
		Files.write(Paths.get(outputFile), decryptedData);
		System.out.println("Archivo descifrado correctamente, almacenado en: " + outputFile);
	}

	public static void main(String[] args) {
		try {
			// ENCRYPT
			RSAUtils rsaUtils = new RSAUtils();
			// leer el archivo de la clave
			String keyFile = Files.readString(Paths.get("encrypt-file/key.key"));
			rsaUtils.encrypt(keyFile, "encrypt-file/keyAES.enc", "encrypt-file/publicKey");

			// DECRYPT
			rsaUtils.decrypt("encrypt-file/keyAES.enc", "encrypt-file/keyAES.dec", "encrypt-file/privateKey");
		} catch (IOException | GeneralSecurityException e) {
			e.printStackTrace();
		}
	}
}
