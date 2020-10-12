package testservice.api;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestOperations;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaAutoConfiguration;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import com.sap.cloud.security.xsuaa.token.authentication.XsuaaJwtDecoderBuilder;

import testservice.api.nohttp.SecurityConfiguration;

@SpringBootTest(classes = { SecurityConfiguration.class, XsuaaAutoConfiguration.class })
@ActiveProfiles({ "test.api.nohttp", "uaamock" })
public class SSRFAttackTest {

	JwtDecoder jwtDecoder;

	@Value("${xsuaa.clientid}")
	String clientId;

	@Value("${xsuaa.xsappname}")
	String xsappname;

	@Autowired
	XsuaaServiceConfiguration serviceConfiguration;

	RestOperations xsuaaRestOperations = Mockito.mock(RestOperations.class);

	@BeforeEach
	public void setUp() {
		jwtDecoder = new XsuaaJwtDecoderBuilder(serviceConfiguration)
				.withRestOperations(xsuaaRestOperations)
				.build();
		// .withPostValidationActions(token -> postActionExecuted = true).build();
	}

	@Test
	public void postValidationActionIsExecutedIfSuccess() {
		String jwt = new JwtGenerator(clientId, "subdomain").deriveAudiences(true)
				.getToken().getTokenValue();
	}

}
