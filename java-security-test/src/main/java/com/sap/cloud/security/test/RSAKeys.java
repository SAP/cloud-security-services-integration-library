package com.sap.cloud.security.test;

import com.sap.cloud.security.test.util.FileReaderUtil;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class to create RSAKeys used for testing.
 */
public class RSAKeys {

	private static final String RSA = "RSA";
	private static final String KEY_BEGIN_END_REGEX = "-+(BEGIN|END)\\s+(\\w+\\s?)+-+";

	private final KeyPair keyPair;

	/**
	 * Generates a random RSA keypair.
	 * 
	 * @return the instance.
	 */
	public static RSAKeys generate() {
		KeyPair theKeyPair = generateKeyPair();
		return new RSAKeys(new KeyPair(theKeyPair.getPublic(), theKeyPair.getPrivate()));
	}

	/**
	 * Creates an instance with the given key pair. The path to the key files must
	 * be specified like described here
	 * {@link FileReaderUtil#fileContentToString(java.lang.String)}. For more
	 * information see {@link RSAKeys#loadPublicKey(String)} and
	 * {@link RSAKeys#loadPrivateKey(String)}.
	 *
	 * @param publicKeyPath
	 *            the path to the key file.
	 * @param privateKeyPath
	 *            the path to the key file.
	 * @return the instance.
	 * @throws IOException
	 *             in case the files could not be read.
	 * @throws NoSuchAlgorithmException
	 *             see {@link KeyFactory#getInstance(java.lang.String)}.
	 * @throws InvalidKeySpecException
	 *             see
	 *             {@link KeyFactory#generatePublic(java.security.spec.KeySpec)}.
	 */
	public static RSAKeys fromKeyFiles(String publicKeyPath, String privateKeyPath)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		KeyPair keyPair = new KeyPair(loadPublicKey(publicKeyPath), loadPrivateKey(privateKeyPath));
		return new RSAKeys(keyPair);
	}

	/**
	 *
	 * @return the public key of the pair.
	 */
	public PublicKey getPublic() {
		return keyPair.getPublic();
	}

	/**
	 *
	 * @return the private key of the pair.
	 */
	public PrivateKey getPrivate() {
		return keyPair.getPrivate();
	}

	private RSAKeys(KeyPair keyPair) {
		this.keyPair = keyPair;
	}

	/**
	 * Loads the public key from the given file. The path to the key file must be
	 * specified like described here
	 * {@link FileReaderUtil#fileContentToString(java.lang.String)}. The key is
	 * expected to be encoded according to the X.509 standard and in base64 format
	 * (pem).
	 *
	 * @param publicKeyPath
	 *            the path to the key file.
	 * @return the {@link PublicKey} instance.
	 * @throws IOException
	 *             in case the file could not be read.
	 * @throws NoSuchAlgorithmException
	 *             see {@link KeyFactory#getInstance(java.lang.String)}.
	 * @throws InvalidKeySpecException
	 *             see
	 *             {@link KeyFactory#generatePublic(java.security.spec.KeySpec)}.
	 */
	public static PublicKey loadPublicKey(String publicKeyPath)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		String publicKeyString = readFileAndReplaceBeginEnd(publicKeyPath);
		X509EncodedKeySpec spec = new X509EncodedKeySpec(base64Decode(publicKeyString));
		return KeyFactory.getInstance(RSA).generatePublic(spec);
	}

	/**
	 * Loads the private key from the given file. The path to the key file must be
	 * specified like described here
	 * {@link FileReaderUtil#fileContentToString(java.lang.String)}. The key is
	 * expected to be according to PKCS #8 standard and in base64 format (pem).
	 *
	 * @param privateKeyPath
	 *            the path to the key file.
	 * @return the {@link PrivateKey} instance.
	 * @throws IOException
	 *             in case the file could not be read.
	 * @throws NoSuchAlgorithmException
	 *             see {@link KeyFactory#getInstance(java.lang.String)}.
	 * @throws InvalidKeySpecException
	 *             see
	 *             {@link KeyFactory#generatePublic(java.security.spec.KeySpec)}.
	 */
	public static PrivateKey loadPrivateKey(String privateKeyPath)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		String privateKeyString = readFileAndReplaceBeginEnd(privateKeyPath);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(base64Decode(privateKeyString));
		return KeyFactory.getInstance(RSA).generatePrivate(spec);
	}

	private static byte[] base64Decode(String publicKeyString) {
		return Base64.getDecoder().decode(publicKeyString);
	}

	private static String readFileAndReplaceBeginEnd(String filePath) throws IOException {
		String content = FileReaderUtil.fileContentToString(filePath);
		String newLinesRemoved = content.replaceAll("\\r|\\n", "");
		return newLinesRemoved.replaceAll(KEY_BEGIN_END_REGEX, "");
	}

	private static KeyPair generateKeyPair() {
		try {
			return KeyPairGenerator.getInstance(RSA).generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException(e);
		}
	}

}
