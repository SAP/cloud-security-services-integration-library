package com.sap.cloud.security.xsuaa.token.authentication;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;
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
@TestPropertySource(properties = {
		"xsuaa.uaadomain=localhost",
		"xsuaa.clientid=sb-clientId!t0815",
		"xsuaa.verificationkey=-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1QaZzMjtEfHdimrHP3/2Yr+1z685eiOUlwybRVG9i8wsgOUh+PUGuQL8hgulLZWXU5MbwBLTECAEMQbcRTNVTolkq4i67EP6JesHJIFADbK1Ni0KuMcPuiyOLvDKiDEMnYG1XP3X3WCNfsCVT9YoU+lWIrZr/ZsIvQri8jczr4RkynbTBsPaAOygPUlipqDrpadMO1momNCbea/o6GPn38LxEw609ItfgDGhL6f/yVid5pFzZQWb+9l6mCuJww0hnhO6gt6Rv98OWDty9G0frWAPyEfuIW9B+mR/2vGhyU9IbbWpvFXiy9RVbbsM538TCjd5JF2dJvxy24addC4oQIDAQAB-----END PUBLIC KEY-----"
})
@ContextConfiguration(classes = XsuaaServiceConfigurationDefault.class)
public class XsuaaJwtDecoderTest {

	@Autowired
	XsuaaServiceConfiguration configuration;

	@Test
	public void decode_withVerficationKey() throws IOException {
		String token = IOUtils.resourceToString("/accessTokenRSA256_verificationKey.txt", StandardCharsets.UTF_8);
		final JwtDecoder cut = new XsuaaJwtDecoderBuilder(configuration).build();

		final Jwt jwt = cut.decode(token);

		assertThat(jwt.getClaimAsString("cid")).isEqualTo("sb-clientId!t0815");
	}

	@Test
	public void decode_withNonMatchingVerificationKey_throwsException() throws IOException {
		String token = IOUtils.resourceToString("/token_cc.txt", StandardCharsets.UTF_8);

		final JwtDecoder cut = new XsuaaJwtDecoderBuilder(configuration).build();

		assertThatThrownBy(() -> cut.decode(token)).isInstanceOf(JwtException.class);
	}
}