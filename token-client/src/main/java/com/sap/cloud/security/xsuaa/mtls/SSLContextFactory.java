package com.sap.cloud.security.xsuaa.mtls;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.xml.bind.DatatypeConverter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Requires https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15on
 * because JDK JCE does not support PKCS#8 algorithm.
 *
 * Add the following maven dependency:
 * <pre>{@code
 * <dependency><!-- crypto lib required for parsing certificate -->
 * 		<groupId>org.bouncycastle</groupId>
 * 		<artifactId>bcprov-jdk15on</artifactId>
 * 		<version>1.56</version>
 * </dependency>
 * }
 * </pre>
 * And before creating the SSLContext using {@link #create(String, String)} you need to add the "BC" Provider.
 * <pre>
 * {@code
 * Security.addProvider(new BouncyCastleProvider());
 * }
 * </pre>
 */
public class SSLContextFactory {
	private static final char[] noPassword = "".toCharArray();
	private static final SSLContextFactory instance = new SSLContextFactory();
	private Logger logger;

	private SSLContextFactory() {
		logger = LoggerFactory.getLogger(getClass());
	}

	public static SSLContextFactory getInstance() {
		return instance;
	}

	public SSLContext create(String x509Certificates, String rsaPrivateKey)
			throws GeneralSecurityException, IOException {
		assertHasText(x509Certificates, "x509Certificates are required");
		assertHasText(rsaPrivateKey, "rsaPrivateKey is required");

		if(Security.getProvider("BC") == null) {
			logger.warn("This method requires BouncyCastleProvider for PKCS#8 support: Security.addProvider(new BouncyCastleProvider())");
			throw new IllegalStateException("This method requires BouncyCastleProvider for PKCS#8 support: Security.addProvider(new BouncyCastleProvider())");
		}

		SSLContext sslContext = createDefaultSSLContext();

		PrivateKey privateKey = getPrivateKeyFromString(rsaPrivateKey);
		Certificate[] certificateChain = getCertificatesFromString(x509Certificates);

		KeyStore keystore = initializeKeyStore(privateKey, certificateChain);

		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
		keyManagerFactory.init(keystore, noPassword);

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

	private PrivateKey getPrivateKeyFromString(final String rsaPrivateKey)
			throws GeneralSecurityException {
		String privateKeyPEM = rsaPrivateKey;
		privateKeyPEM = privateKeyPEM.replace("-----BEGIN RSA PRIVATE KEY-----", "");
		privateKeyPEM = privateKeyPEM.replace("-----END RSA PRIVATE KEY-----", "");
		privateKeyPEM = privateKeyPEM.replace("\n", "");
		logger.debug("privateKeyPem: '{}'", privateKeyPEM);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpec =
				new PKCS8EncodedKeySpec(DatatypeConverter.parseBase64Binary(privateKeyPEM));
		RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

		return privateKey;
	}

	private Certificate[] getCertificatesFromString(String certificates) throws CertificateException {
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		byte[] certificatesBytes = certificates.getBytes();

		Collection<Certificate> certificateList = (Collection<Certificate>) factory
				.generateCertificates(new ByteArrayInputStream(certificatesBytes));
		Certificate[] certificateArray = certificateList.toArray(new Certificate[certificateList.size()]);

		return certificateArray;
	}

}
