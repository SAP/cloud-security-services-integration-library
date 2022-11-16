/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token.authentication;

import com.nimbusds.jwt.JWT;
import com.sap.cloud.security.xsuaa.XsuaaCredentials;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationCustom;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
import com.sap.cloud.security.xsuaa.token.TokenClaims;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.BadJwtException;
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
@TestPropertySource("/XsuaaJwtDecoderTest.properties")
@ContextConfiguration(classes = XsuaaServiceConfigurationDefault.class)
public class XsuaaJwtDecoderTest {

	@Autowired
	XsuaaServiceConfiguration configurationWithVerificationKey;

	XsuaaServiceConfiguration configuration = new XsuaaServiceConfigurationCustom(new XsuaaCredentials());

	@Test
	public void decode_withVerificationKey() throws IOException {
		String token = IOUtils.resourceToString("/accessTokenRSA256WithVerificationKey.txt", StandardCharsets.UTF_8);
		final JwtDecoder cut = new XsuaaJwtDecoderBuilder(configurationWithVerificationKey).build();

		final Jwt jwt = cut.decode(token);
		jwt.getClaimAsString("zid");

		assertThat(jwt.getClaimAsString(TokenClaims.CLAIM_CLIENT_ID)).isEqualTo("sb-clientId!t0815");
	}

	@Test
	public void decode_withInvalidFallbackVerificationKey_withoutUaaDomain() throws IOException {
		XsuaaServiceConfiguration config = Mockito.mock(XsuaaServiceConfiguration.class);
		Mockito.when(config.getVerificationKey()).thenReturn("xsuaa.verificationkey=-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1QaZzMjtEfHdimrHP3/2Yr+1z685eiOUlwybRVG9i8wsgOUh+PUGuQL8hgulLZWXU5MbwBLTECAEMQbcRTNVTolkq4i67EP6JesHJIFADbK1Ni0KuMcPuiyOLvDKiDEMnYG1XP3X3WCNfsCVT9YoU+lWIrZr/ZsIvQri8jczr4RkynbTBsPaAOygPUlipqDrpadMO1momNCbea/o6GPn38LxEw609ItfgDGhL6f/yVid5pFzZQWb+9l6mCuJww0hnhO6gt6Rv98OWDty9G0frWAPyEfuIW9B+mR/2vGhyU9IbbWpvFXiy9RVbbsM538TCjd5JF2dJvxy24addC4oQIDAQAB-----END PUBLIC KEY-----");

		String token = IOUtils.resourceToString("/accessTokenRSA256WithVerificationKey.txt", StandardCharsets.UTF_8);
		final JwtDecoder cut = new XsuaaJwtDecoderBuilder(config).build();

		assertThatThrownBy(() -> cut.decode(token)).isInstanceOf(BadJwtException.class)
				.hasMessageContaining("Jwt validation with fallback verificationkey failed");
	}

	@Test
	public void decode_withFallbackVerificationKey_remoteKeyFetchFailed() throws IOException {
		XsuaaServiceConfiguration config = Mockito.mock(XsuaaServiceConfiguration.class);
		Mockito.when(config.getVerificationKey()).thenReturn("-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1QaZzMjtEfHdimrHP3/2Yr+1z685eiOUlwybRVG9i8wsgOUh+PUGuQL8hgulLZWXU5MbwBLTECAEMQbcRTNVTolkq4i67EP6JesHJIFADbK1Ni0KuMcPuiyOLvDKiDEMnYG1XP3X3WCNfsCVT9YoU+lWIrZr/ZsIvQri8jczr4RkynbTBsPaAOygPUlipqDrpadMO1momNCbea/o6GPn38LxEw609ItfgDGhL6f/yVid5pFzZQWb+9l6mCuJww0hnhO6gt6Rv98OWDty9G0frWAPyEfuIW9B+mR/2vGhyU9IbbWpvFXiy9RVbbsM538TCjd5JF2dJvxy24addC4oQIDAQAB-----END PUBLIC KEY-----");
		Mockito.when(config.getUaaDomain()).thenReturn("localhost");
		Mockito.when(config.getClientId()).thenReturn("sb-clientId!t0815");

		String token = IOUtils.resourceToString("/accessTokenRSA256WithVerificationKey.txt", StandardCharsets.UTF_8);
		final JwtDecoder cut = new XsuaaJwtDecoderBuilder(config).build();
		final Jwt jwt = cut.decode(token);

		assertThat(jwt.getAudience().get(0)).isEqualTo("sb-clientId!t0815");
	}

	@Test
	public void decode_withNonMatchingVerificationKey_throwsException() throws IOException {
		String token = IOUtils.resourceToString("/token_cc.txt", StandardCharsets.UTF_8);

		final JwtDecoder cut = new XsuaaJwtDecoderBuilder(configuration).build();

		assertThatThrownBy(() -> cut.decode(token)).isInstanceOf(JwtException.class)
				.hasMessageContaining("Cannot verify with online token key, jku, kid, uaadomain is null");
	}

	@Test
	public void decode_whenJwksContainsInvalidJwksDomain_throwsException() throws IOException {
		String token = IOUtils.resourceToString("/token_user.txt", StandardCharsets.UTF_8);
		XsuaaJwtDecoder cut = (XsuaaJwtDecoder) new XsuaaJwtDecoderBuilder(configuration).build();

		cut.setTokenInfoExtractor(new TokenInfoExtractorImpl("https://subdomain.wrongoauth.ondemand.com/token_keys"));
		assertThatThrownBy(() -> cut.decode(token)).isInstanceOf(JwtException.class)
				.hasMessageContaining("JWT verification failed: Do not trust 'jku' token header");

		cut.setTokenInfoExtractor(
				new TokenInfoExtractorImpl("http://myauth.ondemand.com@malicious.ondemand.com/token_keys"));
		assertThatThrownBy(() -> cut.decode(token)).isInstanceOf(JwtException.class)
				.hasMessageContaining("JWT verification failed: Do not trust 'jku' token header");

		cut.setTokenInfoExtractor(new TokenInfoExtractorImpl(
				"http://malicious.ondemand.com/token_keys///myauth.ondemand.com/token_keys"));
		assertThatThrownBy(() -> cut.decode(token)).isInstanceOf(JwtException.class)
				.hasMessageContaining("JWT verification failed: Do not trust 'jku' token header");
	}

	@Test
	public void decode_whenJwksUrlIsNotValid_throwsException() throws IOException {
		String token = IOUtils.resourceToString("/token_cc.txt", StandardCharsets.UTF_8);
		XsuaaJwtDecoder cut = (XsuaaJwtDecoder) new XsuaaJwtDecoderBuilder(configuration).build();

		cut.setTokenInfoExtractor(
				new TokenInfoExtractorImpl("http://myauth.ondemand.com\\@malicious.ondemand.com/token_keys"));
		assertThatThrownBy(() -> cut.decode(token)).isInstanceOf(JwtException.class)
				.hasMessageContaining("JWT verification failed: JKU of token header is not valid");
	}

	@Test
	public void decode_whenJwksContainsInvalidPath_throwsException() throws IOException {
		String token = IOUtils.resourceToString("/token_cc.txt", StandardCharsets.UTF_8);

		XsuaaJwtDecoder cut = (XsuaaJwtDecoder) new XsuaaJwtDecoderBuilder(configuration).build();
		cut.setTokenInfoExtractor(new TokenInfoExtractorImpl("https://subdomain.myauth.ondemand.com/wrong_endpoint"));

		assertThatThrownBy(() -> cut.decode(token)).isInstanceOf(JwtException.class)
				.hasMessageContaining("Jwt token does not contain a valid 'jku' header parameter");
	}

	@Test
	public void decode_whenJwksContainQueryParameters_throwsException() throws IOException {
		String token = IOUtils.resourceToString("/token_cc.txt", StandardCharsets.UTF_8);

		XsuaaJwtDecoder cut = (XsuaaJwtDecoder) new XsuaaJwtDecoderBuilder(configuration).build();
		cut.setTokenInfoExtractor(new TokenInfoExtractorImpl("https://subdomain.myauth.ondemand.com/token_keys?a=b"));

		assertThatThrownBy(() -> cut.decode(token)).isInstanceOf(JwtException.class)
				.hasMessageContaining("Jwt token does not contain a valid 'jku' header parameter: ");

	}

	@Test
	public void decode_whenJwksContainsFragment_throwsException() throws IOException {
		String token = IOUtils.resourceToString("/token_cc.txt", StandardCharsets.UTF_8);

		XsuaaJwtDecoder cut = (XsuaaJwtDecoder) new XsuaaJwtDecoderBuilder(configuration).build();
		cut.setTokenInfoExtractor(
				new TokenInfoExtractorImpl("https://subdomain.myauth.ondemand.com/token_keys#token_keys"));

		assertThatThrownBy(() -> cut.decode(token)).isInstanceOf(JwtException.class)
				.hasMessageContaining("Jwt token does not contain a valid 'jku' header parameter:");

	}

	private static class TokenInfoExtractorImpl
			implements com.sap.cloud.security.xsuaa.token.authentication.TokenInfoExtractor {
		private String jku;

		public TokenInfoExtractorImpl(String jku) {
			this.jku = jku;
		}

		@Override
		public String getJku(JWT jwt) {
			return jku;
		}

		@Override
		public String getKid(JWT jwt) {
			return "kid";
		}

		@Override
		public String getUaaDomain(JWT jwt) {
			return "myauth.ondemand.com";
		}
	}
}