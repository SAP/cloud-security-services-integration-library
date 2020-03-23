package com.sap.cloud.security.xsuaa.token.authentication;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import com.sap.cloud.security.xsuaa.token.TokenClaims;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@RunWith(SpringRunner.class)
@TestPropertySource(
		locations = "/XsuaaJwtDecoderTest.properties"
)
@ContextConfiguration(classes = XsuaaServiceConfigurationDefault.class)
public class XsuaaJwtDecoderTest {

	@Autowired
	XsuaaServiceConfiguration configuration;

	@Test
	public void decode_withVerficationKey() throws IOException {
		String token = IOUtils.resourceToString("/accessTokenRSA256WithVerificationKey.txt", StandardCharsets.UTF_8);
		final JwtDecoder cut = new XsuaaJwtDecoderBuilder(configuration).build();

		final Jwt jwt = cut.decode(token);

		assertThat(jwt.getClaimAsString(TokenClaims.CLAIM_CLIENT_ID)).isEqualTo("sb-clientId!t0815");
	}

	@Test
	public void decode_withNonMatchingVerificationKey_throwsException() throws IOException {
		String token = IOUtils.resourceToString("/token_cc.txt", StandardCharsets.UTF_8);

		final JwtDecoder cut = new XsuaaJwtDecoderBuilder(configuration).build();

		assertThatThrownBy(() -> cut.decode(token)).isInstanceOf(JwtException.class);
	}
}