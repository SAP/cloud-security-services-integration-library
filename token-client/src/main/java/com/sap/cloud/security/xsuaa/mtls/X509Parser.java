package com.sap.cloud.security.xsuaa.mtls;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class X509Parser {
	public static final Logger LOGGER = LoggerFactory.getLogger(X509Parser.class);

	private X509Parser() {
	}

	/**
	 * Generates X509 thumbprint from provided certificate as specified in JWT
	 * Certificate Thumbprint Confirmation Method
	 * 
	 * @see <a href="https://tools.ietf.org/html/rfc8705#section-3.1"></a>
	 * @param certificate
	 *            Base64 encoded X509 certificate
	 * @return Thumbprint of X509 certificate
	 * @throws NoSuchAlgorithmException
	 *             when a particular cryptographic algorithm is requested but is not
	 *             available in the environment
	 * @throws CertificateException is thrown if errors occur while decoding X509 certificate
	 */
	public static String getX509Thumbprint(String certificate) throws NoSuchAlgorithmException, CertificateException {
		X509Certificate x509Certificate;

		x509Certificate = decodeX509(certificate);
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hashedX509 = digest.digest(x509Certificate.getEncoded());
		String base64UrlEncoding = normalizeThumbprint(Base64.getUrlEncoder().encodeToString(hashedX509));
		LOGGER.debug("Base64-url encoded thumbprint: {}", base64UrlEncoding);
		return base64UrlEncoding;
	}

	public static String getJwtThumbprint(String base64cert) throws NoSuchAlgorithmException {
		base64cert = base64cert
				.replace("-----BEGIN CERTIFICATE-----", "")
				.replace("-----END CERTIFICATE-----", "")
				.replace("\n", "")
				.replace(" ", "");
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] der = Base64.getDecoder().decode(base64cert.getBytes(StandardCharsets.US_ASCII));
		byte[] hashedX509 = sha256.digest(der);
		return normalizeThumbprint(Base64.getUrlEncoder().encodeToString(hashedX509));
	}

	/**
	 * The base64url-encoded value MUST omit all trailing pad '=' characters and
	 * MUST NOT include any line breaks, whitespace, or other additional characters
	 *
	 * @param thumbprint
	 *            raw thumbprint of X509
	 * @return thumbprint without trailing '=' and '\n'
	 */
	static String normalizeThumbprint(String thumbprint) {
		return thumbprint.trim().replaceFirst("=*$", "").replace("\n", "").replace("\\n", "");
	}

	/**
	 * @param encodedX509
	 *            base64 encoded X509 certificate
	 * @return Decoded X509Certificate
	 * @throws CertificateException
	 *             if String value od cert cannot be parsed
	 */
	private static X509Certificate decodeX509(String encodedX509) throws CertificateException {
		String encodedPemX509 = encodePemLabels(encodedX509);

		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream bytes = new ByteArrayInputStream(encodedPemX509.getBytes(StandardCharsets.UTF_8));

		return (X509Certificate) certFactory.generateCertificate(bytes);
	}

	@Nonnull
	private static String encodePemLabels(String base64EncodedCert) throws CertificateException {
		if (base64EncodedCert == null) {
			throw new CertificateException("Base64 encoded certificate is missing");
		}

		if (!base64EncodedCert.startsWith("-----BEGIN CERTIFICATE-----")
				&& !base64EncodedCert.endsWith("-----END CERTIFICATE-----")) {
			base64EncodedCert = "-----BEGIN CERTIFICATE-----\n" + base64EncodedCert + "\n-----END CERTIFICATE-----";
		}
		LOGGER.debug("PEM encoded certificate: {}", base64EncodedCert);
		return base64EncodedCert;
	}

}
