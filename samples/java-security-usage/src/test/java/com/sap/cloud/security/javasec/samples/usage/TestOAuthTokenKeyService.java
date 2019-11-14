package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySet;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySetFactory;
import org.apache.commons.io.IOUtils;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class TestOAuthTokenKeyService implements OAuth2TokenKeyService {

	private static final String PRIVATE_KEY = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQClpyfd98VmK+s5DYwdePzPwrh9Og//enONRyxGwXY8XV2cSlupvPEyhx5uh4M/W2jH519fCi5JQZPfhLz75EA9AQZpkgiZdVssciu70ucUPTgcnlxupwGE6G/gz6NwA2tif/joibgUpQMv6L4j4IAoWOhvLZlBgpVSpMkIQL8XFN2MdyCjUAYwo+OdBVie8kCZT4NX9B1qOlEwXPy79jzXlkt/pcXs2qpoAnLRQoP7vSNkY2d5kJekAlYFtrHM7pfaq6xpl0ttuK/dPvMK75n7JBzsRH1VGUG1rXWceRf8iG25oaL1vZfXlJy4g2tgJodCXjvQZhiUsuUXClA1n96fAgMBAAECggEAOYDjJ/yAu8z3JKD9SKXdLMntfRsQvqDlR9+zEQTLZH0Mp9pwI2YBXIbnG3tTJkU3BF3fD4DbPHbVPDw51j8PxZ17el5FOfAxLCad4998c9wkhFq8v3Sd5GNDowixNYsaVeESqLZV/mShzJnAl3exRVBHr4BmuQT5jOzDFGhVbU8y1Ji25q1594UgLt68j79Ja+EKpVVurstOalXgNLAG6LIsI+pMqAudk0v7No0IdAGETDBx6yPfXxBBS5mU27NgRIpIFv0D2YPTApyuGcWB2NSL2TrdEL3n9E0ha96p3jDqy8o/H1Irjqz+RUeFKM1vI8L6ExjHy1Ec3TJaCBKT8QKBgQDpoDy3H+2P2njUjkEL1Et8+n6ZErT9NIPL58HaxKrZ1rs20Djafx3FAVmbtsV3hICWX+SRXyjHIjpps29M3drDIrJ/1wzD9LPyog4E+oQ8k3ToHPzvxcvEftiA/bs2ggIvLWwqYN/4IsXkwMqixsupuXS5u+sTHJSeDlzpiHUKZQKBgQC1hHAdrTIRdKxg9ImcrkBOVMSNvwXfJNV/QZS8KtRWUxnoH5aA3Hv+mM6H/Zx0fznv0erRBYXUv/2G9VJCX5/zU7pJYz6hmHwf+vyHdN2m7TpCleetHe58T8c69gRe9apmSNDQ8WTN8g+ubBmequzQbFQvnnmA42RKP6rG0KySswKBgDXoJVpT4ar5zDuvf07Nc4Wo/yEu8dgjD+4y0cY67vlI1PX24cd44VOd1iFZ8QJ87nbENaddf7lDKptNLfdckafJD8rzwhxNEGCCCB4Z9/1KQQV1+t8Qks4KPsa0xUf0g7CDGJxGsic9TtBTs+4PVNsa0dYxiDJmu9wkkEfKlscJAoGAIMP1UQYQgaIj86Rwqr2xkfIvQL74ml0VxNDbvlOk3KhHhuUcz8n8/+opbdbTxRuqI6Yq0uxCSjMV2qSx4pVMVCoK+HBXv+e8kDFIIFNyJ02vNJHGrjM2922XMwdxpoqF5czDFNReM+a7+eo9fayw7rZ/Q9FBcYiac+SmORk17Y0CgYA2i1DY0SZv+WeXsKrlQkrVHOg5sh6+6B/z6hgM65wg3ikBVk6xCu+cLSIDLO6uKpIaCjDs5QmNegMXGlfw09y69GHOm9IC/OIe3+UDJdXRzZwmBxBgGD25xge4LeioPcO+jHVoTt4qGiFtBHrG5Ds3iNkGPhzKlbnmAiS2P2+gSg==";
	private static final String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApacn3ffFZivrOQ2MHXj8z8K4fToP/3pzjUcsRsF2PF1dnEpbqbzxMoceboeDP1tox+dfXwouSUGT34S8++RAPQEGaZIImXVbLHIru9LnFD04HJ5cbqcBhOhv4M+jcANrYn/46Im4FKUDL+i+I+CAKFjoby2ZQYKVUqTJCEC/FxTdjHcgo1AGMKPjnQVYnvJAmU+DV/QdajpRMFz8u/Y815ZLf6XF7NqqaAJy0UKD+70jZGNneZCXpAJWBbaxzO6X2qusaZdLbbiv3T7zCu+Z+yQc7ER9VRlBta11nHkX/IhtuaGi9b2X15ScuINrYCaHQl470GYYlLLlFwpQNZ/enwIDAQAB";

	private static final String RSA = "RSA";

	private final PrivateKey privateKey;
	private final PublicKey publicKey;

	public TestOAuthTokenKeyService() throws NoSuchAlgorithmException, InvalidKeySpecException {
		privateKey = createPrivateKey();
		publicKey = createPublicKey();
	}

	@Override
	public JsonWebKeySet retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri) {
		return JsonWebKeySetFactory.createFromJson(createTokenKeyResponse());
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	private PublicKey createPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] decoded = decode(PUBLIC_KEY);
		X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
		KeyFactory kf = KeyFactory.getInstance(RSA);
		return kf.generatePublic(spec);
	}

	private PrivateKey createPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] decoded = decode(PRIVATE_KEY);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	private byte[] decode(String privateKey) {
		return Base64.getDecoder().decode(privateKey);
	}

	private String createTokenKeyResponse() {
		try {
			return IOUtils.resourceToString("/token_keys_template.json", StandardCharsets.UTF_8)
					.replace("$kid", "default-kid")
					.replace("$public_key", Base64.getEncoder().encodeToString(publicKey.getEncoded()));
		} catch (IOException e) {
			throw new RuntimeException("Failed to load token key template!");
		}
	}

}
