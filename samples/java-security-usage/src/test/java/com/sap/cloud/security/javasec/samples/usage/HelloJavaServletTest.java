package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.test.RSAKeys;
import com.sap.cloud.security.test.SecurityIntegrationTestRule;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.junit.*;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static com.sap.cloud.security.config.Service.XSUAA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class HelloJavaServletTest {

	@Rule
	public SecurityIntegrationTestRule rule = SecurityIntegrationTestRule.getInstance(XSUAA).setPort(8181);

	private static Properties oldProperties;

	private TokenFilter cut;
	private FilterChain filterChain;
	private HttpServletResponse httpResponse;
	private HttpServletRequest httpRequest;

	@BeforeClass
	public static void prepareTest() throws Exception {
		oldProperties = System.getProperties();
		System.setProperty(CFConstants.VCAP_SERVICES, IOUtils.resourceToString("/vcap.json", StandardCharsets.UTF_8));
	}

	@AfterClass
	public static void restoreProperties() {
		System.setProperties(oldProperties);
	}

	@Before
	public void setUp() {
		cut = new TokenFilter();
		httpResponse = mock(HttpServletResponse.class);
		httpRequest = mock(HttpServletRequest.class);
		filterChain = mock(FilterChain.class);
	}

	@After
	public void tearDown()  {
		SecurityContext.clearToken();
	}

	@Test
	public void validBearerToken_isAuthorized() throws IOException, ServletException {
		Token token = rule.getPreconfiguredJwtGenerator().createToken();
		mockAuthorizationHeader(token);

		cut.doFilter(httpRequest, httpResponse, filterChain);

		verify(filterChain, times(1)).doFilter(httpRequest, httpResponse);
		assertThat(SecurityContext.getToken().getAccessToken()).isEqualTo(token.getAccessToken());
	}

	@Test
	public void wrongPrivateKey_isNotAuthorized() {
		Token token = rule.getPreconfiguredJwtGenerator()
				.withPrivateKey(RSAKeys.generate().getPrivate())
				.createToken();
		mockAuthorizationHeader(token);

		cut.doFilter(httpRequest, httpResponse, filterChain);

		verifyNoInteractions(filterChain);
		verify(httpResponse, times(1)).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		assertThat(SecurityContext.getToken()).isNull();
	}

	private void mockAuthorizationHeader(Token token) {
		when(httpRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + token.getAccessToken());
	}

}