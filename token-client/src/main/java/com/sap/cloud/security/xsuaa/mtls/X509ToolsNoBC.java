package com.sap.cloud.security.xsuaa.mtls;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

import org.apache.commons.codec.Charsets;

public class X509ToolsNoBC {
	//
	// Certificates
	//

	@SuppressWarnings("unchecked")
	public static Collection<X509Certificate> readX509Certificates(Path path)
			throws CertificateException, IOException {
		try (InputStream fis = Files.newInputStream(path)) {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			return (Collection<X509Certificate>) factory.generateCertificates(fis);
		}
	}

	public static void writeX509Certificates(Path path, X509Certificate... certificates)
			throws CertificateEncodingException, IOException {
		try (OutputStream out = Files.newOutputStream(path)) {
			for (X509Certificate certificate : certificates) {
				writeMaterial(out, B_CERTIFICATE, certificate.getEncoded());
			}
		}
	}

	//
	// PKCS8
	//

	public static void writePKCS8PrivateKey(OutputStream out, PrivateKey privateKey) throws IOException {
		writeMaterial(out, B_PKCS8, privateKey.getEncoded());
	}

	public static void writePKCS8PrivateKey(Path path, PrivateKey privateKey) throws IOException {
		try (OutputStream out = Files.newOutputStream(path)) {
			writePKCS8PrivateKey(out, privateKey);
		}
	}

	//
	// PKCS 1 & 8
	//
	public static PrivateKey readPKCSPrivateKey(Path privateKeyPath)
			throws IOException, GeneralSecurityException {
		List<PEMEntry> pemData = readPEM(privateKeyPath);
		if (pemData.isEmpty()) {
			throw new IOException("No PEM content");
		}

		PEMEntry entry = pemData.get(0);
		return decodePrivateKey(entry.getType(), entry.getData());
	}

	//////////////////
	private static final String MARKER_BEGIN = "-----BEGIN ";
	private static final String MARKER_END = "-----END ";
	private static final String MARKER_EOL = "-----";

	private static final String PKCS8 = "PRIVATE KEY";
	private static final String PKCS1 = "RSA PRIVATE KEY";
	private static final String CERTIFICATE = "CERTIFICATE";

	private static final byte[] B_LINE_SEPARATOR = System.getProperty("line.separator").getBytes(Charsets.US_ASCII);
	private static final byte[] B_MARKER_BEGIN = MARKER_BEGIN.getBytes(Charsets.US_ASCII);
	private static final byte[] B_MARKER_END = MARKER_END.getBytes(Charsets.US_ASCII);
	private static final byte[] B_MARKER_EOL = MARKER_EOL.getBytes(Charsets.US_ASCII);
	@SuppressWarnings("unused")
	private static final byte[] B_PKCS1 = PKCS1.getBytes(Charsets.US_ASCII);
	private static final byte[] B_PKCS8 = PKCS8.getBytes(Charsets.US_ASCII);
	private static final byte[] B_CERTIFICATE = CERTIFICATE.getBytes(Charsets.US_ASCII);

	private X509ToolsNoBC() {

	}

	private static void write(OutputStream out, byte[]... content) throws IOException {
		for (byte[] data : content) {
			out.write(data);
		}
	}

	private static void writeMaterial(OutputStream out, byte[] type, byte[] encodedContent)
			throws IOException {
		byte[] content = Base64.getMimeEncoder(64, B_LINE_SEPARATOR).encode(encodedContent);
		write(out//
				, B_MARKER_BEGIN, type, B_MARKER_EOL, B_LINE_SEPARATOR //
				, content, B_LINE_SEPARATOR //
				, B_MARKER_END, type, B_MARKER_EOL, B_LINE_SEPARATOR //
		);
	}

	private static List<PEMEntry> readPEM(Path path) throws IOException {
		List<PEMEntry> res = new ArrayList<>();

		try (BufferedReader reader = Files.newBufferedReader(path)) {
			StringBuffer sb = new StringBuffer(4096);

			String line;
			String type = null;
			while ((line = reader.readLine()) != null) {
				if (type == null) {
					if (!line.startsWith(MARKER_BEGIN) || !line.endsWith(MARKER_EOL)) {
						throw new IOException("Format unknown");
					}
					type = line.substring(MARKER_BEGIN.length(), line.length() - MARKER_EOL.length()).trim();
				} else if (line.startsWith(MARKER_END) && line.endsWith(MARKER_EOL)) {
					byte[] decode = Base64.getDecoder().decode(sb.toString());
					res.add(new PEMEntry(type, decode));
					sb.setLength(0);
					type = null;
				} else {
					sb.append(line);
				}
			}
			// Ignore rest
		}
		return res;
	}

	private static PrivateKey decodePrivateKey(String format, byte[] data)
			throws IOException, GeneralSecurityException {

		KeySpec keySpec;

		switch (format) {
		case PKCS1:
			// import sun.security.util.DerInputStream;
			// import sun.security.util.DerValue;

			// @SuppressWarnings("restriction")
			//
			// DerInputStream derReader = new DerInputStream(data);
			//
			// DerValue[] seq = derReader.getSequence(0);
			// @SuppressWarnings("unused")
			// BigInteger version = seq[0].getBigInteger();
			//
			// BigInteger modulus = seq[1].getBigInteger();
			// BigInteger publicExponent = seq[2].getBigInteger();
			// BigInteger privateExponent = seq[3].getBigInteger();
			// BigInteger primeP = seq[4].getBigInteger();
			// BigInteger primeQ = seq[5].getBigInteger();
			// BigInteger primeExponentP = seq[6].getBigInteger();
			// BigInteger primeExponentQ = seq[7].getBigInteger();
			// BigInteger crtCoefficient = seq[8].getBigInteger();

			MinimalDERParser dp = new MinimalDERParser(data);
			dp.getSequence();
			BigInteger version = dp.getBigInteger();
			if (!version.equals(BigInteger.ZERO)) {
				throw new IOException("Only version 0 supported for PKCS1 decoding.");
			}
			BigInteger modulus = dp.getBigInteger();
			BigInteger publicExponent = dp.getBigInteger();
			BigInteger privateExponent = dp.getBigInteger();
			BigInteger primeP = dp.getBigInteger();
			BigInteger primeQ = dp.getBigInteger();
			BigInteger primeExponentP = dp.getBigInteger();
			BigInteger primeExponentQ = dp.getBigInteger();
			BigInteger crtCoefficient = dp.getBigInteger();

			keySpec = new RSAPrivateCrtKeySpec(
					modulus,
					publicExponent,
					privateExponent,
					primeP,
					primeQ,
					primeExponentP,
					primeExponentQ,
					crtCoefficient);
			break;

		case PKCS8:
			keySpec = new PKCS8EncodedKeySpec(data);
			break;

		default:
			throw new IOException("Unknown format: " + format);
		}

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return privateKey;
	}

}
