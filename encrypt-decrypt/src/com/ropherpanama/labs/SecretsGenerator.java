package com.ropherpanama.labs;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Clase de utilidades para generar:
 * <ul>
 * <li>Archivos de llave para cifrado AES</li>
 * <li>Archivos de clave pública y privada para cifrado RSA</li>
 * </ul>
 *
 * @author ropherpanama
 */

public class SecretsGenerator {
	/**
	 * Use este metodo para generar llaves de manera aleatoria, puede definir una
	 * cantidad de bytes de acuerdo a su necesidad, sin embargo se recomienda un
	 * maximo de 64
	 * 
	 * @param outputFile Archivo destino en donde se almacenara la llave resultado
	 *                   de la creacion (incluya la ruta completa y el nombre del
	 *                   archivo
	 * @param byteSize   Tamaño de la llave a generar, ejm: 64 bytes
	 */
	public void generateAESRandomKey(String outputFile, int byteSize) {
		try {
			// Generar bytes aleatorios
			byte[] randomBytes = new byte[byteSize];
			SecureRandom secureRandom = new SecureRandom();
			secureRandom.nextBytes(randomBytes);
			String base64Key = Base64.getEncoder().encodeToString(randomBytes);

			saveKeyToFile(outputFile, base64Key.getBytes(StandardCharsets.UTF_8));

			System.out.println("Clave generada correctamente, almacenada en : " + outputFile);
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Error al generar la clave.");
		}
	}

	/**
	 * Use este metodo para generar un par de llaves (publica y privada)
	 * 
	 * @param outputDir directorio donde se almacenara cada una de las llaves, se
	 *                  creara un archivo publicKey y un privateKey
	 * @param keySize   tamaño en bytes de las llaves a generar
	 */
	public void generatePublicPrivateKeyPair(String outputDir, int keySize) {
		try {
			KeyPair pair = generateKeyPair(keySize);
			saveKeyToFile(outputDir + "/publicKey", pair.getPublic().getEncoded());
			saveKeyToFile(outputDir + "/privateKey", pair.getPrivate().getEncoded());

			System.out.println("Par de claves generadas correctamente, alamcenada en : " + outputDir);
		} catch (Exception e) {
			System.err.println("Error al generar el par de claves: " + e.getMessage());
			e.printStackTrace();
		}
	}

	private KeyPair generateKeyPair(int keySize) throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(keySize);
		return keyGen.generateKeyPair();
	}

	private void saveKeyToFile(String filePath, byte[] keyData) throws Exception {
//		Files.write(Paths.get(filePath), keyData);
		Path path = Paths.get(filePath);
		Path parentDir = path.getParent();

		if (parentDir != null && !Files.exists(parentDir)) {
			Files.createDirectories(parentDir);
		}

		Files.write(path, keyData);
	}

	public static void main(String[] args) {
		SecretsGenerator secretsGenerator = new SecretsGenerator();
		secretsGenerator.generateAESRandomKey("encrypt-file/key.key", 32);
		secretsGenerator.generatePublicPrivateKeyPair("encrypt-file/", 1024);
	}
}
