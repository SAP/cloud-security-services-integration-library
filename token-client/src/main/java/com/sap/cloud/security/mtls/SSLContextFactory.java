/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.mtls;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.Collection;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

/**
 * Creates a SSLContext (without Bouncy Castle crypto lib).
 */
public class SSLContextFactory {
	private static final char[] noPassword = "".toCharArray();
	private static final SSLContextFactory instance = new SSLContextFactory();
	private final Logger logger;

	private SSLContextFactory() {
		logger = LoggerFactory.getLogger(getClass());
	}

	public static SSLContextFactory getInstance() {
		return instance;
	}

	private static String removeHeaders(String privateKey) {
		return privateKey
				.replace("-----BEGIN RSA PRIVATE KEY-----", "")
				.replace("-----BEGIN PRIVATE KEY-----", "")
				.replace("-----END RSA PRIVATE KEY-----", "")
				.replace("-----END PRIVATE KEY-----", "")
				.replace("\\n", "")
				.replace("\n", "")
				.replace("\\r", "")
				.replace("\r", "");
	}

	/**
	 * Creates a SSLContext which can be used to parameterize your Rest client, in order to support mutual TLS.
	 *
	 * @param x509Certificates
	 * 		you can get from your Service Configuration {@link OAuth2ServiceConfiguration#getClientIdentity()}
	 * @param privateKey
	 * 		you can get from your Service Configuration{@link OAuth2ServiceConfiguration#getClientIdentity()} PKCS#1 (RSA
	 * 		algorithm) and PKCS#8 (ECC algorithm) key encryption standards are supported.
	 * @return a new SSLContext instance
	 * @throws GeneralSecurityException
	 * 		in case of key parsing errors
	 * @throws IOException
	 * 		in case of KeyStore initialization errors
	 */
	public SSLContext create(String x509Certificates, String privateKey)
			throws GeneralSecurityException, IOException {
		assertHasText(x509Certificates, "x509Certificate is required");
		assertHasText(privateKey, "privateKey is required");

		return create(new ClientCertificate(x509Certificates, privateKey, null));
	}

	/**
	 * Creates a SSLContext which can be used to parameterize your Rest client, in order to support mutual TLS.
	 *
	 * @param clientIdentity
	 * 		you can get from your Service Configuration {@link OAuth2ServiceConfiguration#getClientIdentity()}
	 * 		PKCS#1 (RSA algorithm) and PKCS#8 (ECC algorithm) key encryption standards are supported.
	 * @return a new SSLContext instance
	 * @throws GeneralSecurityException
	 * 		in case of key parsing errors
	 * @throws IOException
	 * 		in case of KeyStore initialization errors
	 */
	public SSLContext create(ClientIdentity clientIdentity) throws GeneralSecurityException, IOException {
		KeyStore keystore = createKeyStore(clientIdentity);
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
		keyManagerFactory.init(keystore, noPassword);
		SSLContext sslContext = createDefaultSSLContext();
		sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
		return sslContext;
	}

	private KeyStore initializeKeyStore(PrivateKey privateKey, Certificate[] certificateChain)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		KeyStore keystore = KeyStore.getInstance("jks");
		keystore.load(null); // there is no data in the keystore file - loads empty keystore
		int i = 0;
		for (Certificate certificate : certificateChain) {
			keystore.setCertificateEntry("cert-alias-" + "" + i++, certificate);
		}
		keystore.setKeyEntry("key-alias", privateKey, noPassword, certificateChain);

		return keystore;
	}

	private SSLContext createDefaultSSLContext() throws NoSuchAlgorithmException {
		return SSLContext.getInstance("TLS");
	}

	/**
	 * Initializes a KeyStore which can be used to parameterize your Rest client, in order to support mutual TLS.
	 *
	 * @param clientIdentity
	 * 		you can get from your Service Configuration {@link OAuth2ServiceConfiguration#getClientIdentity()}
	 * 		PKCS#1 (RSA algorithm) and PKCS#8 (ECC algorithm) key encryption standards are supported.
	 * @return a new KeyStore instance
	 * @throws GeneralSecurityException
	 * 		in case of key parsing errors
	 * @throws IOException
	 * 		in case of KeyStore initialization errors
	 */
	public KeyStore createKeyStore(ClientIdentity clientIdentity) throws GeneralSecurityException, IOException {
		assertNotNull(clientIdentity, "clientIdentity must not be null");
		try {
			assertHasText(clientIdentity.getCertificate(), "clientIdentity.getCertificate() must not return null");
			assertHasText(clientIdentity.getKey(), "clientIdentity.getKey() must not return null");
		} catch (IllegalArgumentException e) {
			logger.debug(
					"clientIdentity.getCertificate() or clientIdentity.getKey() is null. Trying to use certificateChain and privateKey instead.");
			assertNotNull(clientIdentity.getCertificateChain(),
					e.getMessage() + " or clientIdentity.getCertificateChain() must not return null");
			assertNotNull(clientIdentity.getPrivateKey(),
					e.getMessage() + " or clientIdentity.getKey() or clientIdentity.getPrivateKey() must not return null");
		}
		Certificate[] certificateChain = getCertificateChain(clientIdentity);
		PrivateKey privateKey = getPrivateKey(clientIdentity);

		return initializeKeyStore(privateKey, certificateChain);
	}

	private PrivateKey getPrivateKey(final ClientIdentity clientIdentity) throws GeneralSecurityException {
		KeySpec keySpec = null;
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		String pemPrivateKey = clientIdentity.getKey();
		PrivateKey privateKey = clientIdentity.getPrivateKey();

		if (pemPrivateKey != null) {
			if (pemPrivateKey.startsWith("-----BEGIN RSA PRIVATE")) {
				keySpec = parsePKCS1PrivateKey(Base64.getDecoder().decode(removeHeaders(pemPrivateKey)));
			} else {
				keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(removeHeaders(pemPrivateKey)));
				keyFactory = KeyFactory.getInstance("EC");
			}
			if (logger.isDebugEnabled()) {
				logger.debug("PEM private key: '{}...{}'", pemPrivateKey.substring(5, 40),
						pemPrivateKey.substring(pemPrivateKey.length() - 25));
			}
		} else if (privateKey != null && privateKey.getAlgorithm().equals("EC")) {
			keyFactory = KeyFactory.getInstance("EC");
			keySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		}
		logger.debug("Private key encoding algorithm: {}", keyFactory.getAlgorithm());

		return keyFactory.generatePrivate(keySpec);
	}

	private Certificate[] getCertificateChain(ClientIdentity clientIdentity) throws CertificateException {
		String certificates = clientIdentity.getCertificate();
		Certificate[] certificateChain = null;
		if (clientIdentity.getCertificate() != null) {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			byte[] certificatesBytes = certificates.replace("\\n", "\n").getBytes();

			Collection<Certificate> certificateList = (Collection<Certificate>) factory
					.generateCertificates(new ByteArrayInputStream(certificatesBytes));
			if (logger.isDebugEnabled()) {
				logger.debug("PEM Certificate: '{}...{}'", certificates.substring(5, 40),
						certificates.substring(certificates.length() - 25));
			}
			certificateChain = certificateList.toArray(new Certificate[0]);
		} else if (clientIdentity.getCertificateChain() != null) {
			certificateChain = clientIdentity.getCertificateChain();
		}
		return certificateChain;
	}

	private KeySpec parsePKCS1PrivateKey(byte[] privateKeyDerEncoded)
			throws GeneralSecurityException {
		KeySpec keySpec;

		MinimalDERParser parser = new MinimalDERParser(privateKeyDerEncoded);

		try {
			parser.getSequence();

			BigInteger version = parser.getBigInteger();
			if (!version.equals(BigInteger.ZERO)) {
				throw new IllegalArgumentException("Only version 0 supported for PKCS1 decoding.");
			}
			BigInteger modulus = parser.getBigInteger();
			BigInteger publicExponent = parser.getBigInteger();
			BigInteger privateExponent = parser.getBigInteger();
			BigInteger primeP = parser.getBigInteger();
			BigInteger primeQ = parser.getBigInteger();
			BigInteger primeExponentP = parser.getBigInteger();
			BigInteger primeExponentQ = parser.getBigInteger();
			BigInteger crtCoefficient = parser.getBigInteger();

			keySpec = new RSAPrivateCrtKeySpec(
					modulus,
					publicExponent,
					privateExponent,
					primeP,
					primeQ,
					primeExponentP,
					primeExponentQ,
					crtCoefficient);
		} catch (IOException e) {
			throw new GeneralSecurityException("Exception during parsing DER encoded private key", e);
		}
		return keySpec;
	}
}
