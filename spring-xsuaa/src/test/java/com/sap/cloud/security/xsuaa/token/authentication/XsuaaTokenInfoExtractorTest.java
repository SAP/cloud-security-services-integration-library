package com.sap.cloud.security.xsuaa.token.authentication;

import com.nimbusds.jwt.SignedJWT;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import org.junit.Before;
import org.junit.Test;

import java.text.ParseException;

import static org.assertj.core.api.Assertions.*;

public class XsuaaTokenInfoExtractorTest {

	private static final String UAA_DOMAIN = "theUaaDomain";

	private XsuaaTokenInfoExtractor cut;
	private JwtGenerator jwtGenerator;

	@Before
	public void setUp() throws Exception {
		cut = new XsuaaTokenInfoExtractor(UAA_DOMAIN);
		jwtGenerator = new JwtGenerator();
	}

	@Test
	public void getJku() throws ParseException {
		String jku = "theJku";
		jwtGenerator.setJku(jku);

		SignedJWT jwt = createJWT();

		assertThat(cut.getJku(jwt)).isEqualTo(jku);
	}

	@Test
	public void getKid() throws ParseException {
		String keyId = "theKeyId";
		jwtGenerator.setJwtHeaderKeyId(keyId);

		SignedJWT jwt = createJWT();

		assertThat(cut.getKid(jwt)).isEqualTo(keyId);
	}

	@Test
	public void getUaaDomain() {
		assertThat(cut.getUaaDomain(null)).isEqualTo(UAA_DOMAIN);
	}

	private SignedJWT createJWT() throws ParseException {
		return SignedJWT.parse(jwtGenerator.getToken().getTokenValue());
	}
}