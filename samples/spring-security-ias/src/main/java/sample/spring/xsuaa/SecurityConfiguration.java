package sample.spring.xsuaa;

import javax.net.ssl.SSLContext;

import java.util.concurrent.TimeUnit;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.web.client.RestTemplate;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import com.sap.cloud.security.xsuaa.extractor.AuthenticationInformationExtractor;
import com.sap.cloud.security.xsuaa.extractor.AuthenticationMethod;
import com.sap.cloud.security.xsuaa.extractor.DefaultAuthenticationInformationExtractor;
import com.sap.cloud.security.xsuaa.mtls.SSLContextFactory;
import com.sap.cloud.security.xsuaa.extractor.TokenBrokerResolver;
import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;


@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	XsuaaServiceConfiguration xsuaaServiceConfiguration;

	Logger logger = LoggerFactory.getLogger(SecurityConfiguration.class);

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// @formatter:off
		http.authorizeRequests()
				.antMatchers("/hello-token").hasAuthority("uaa.resource")
				.anyRequest().authenticated()
			.and()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
				.oauth2ResourceServer()
				.bearerTokenResolver(getTokenBrokerResolver())
				.jwt()
				.jwtAuthenticationConverter(jwtAuthenticationConverter());
		// @formatter:on
	}

	BearerTokenResolver getTokenBrokerResolver() throws Exception {
		Cache cache = new CaffeineCache("token",
				Caffeine.newBuilder()
						.expireAfterWrite(15, TimeUnit.MINUTES)
						.maximumSize(100).build(), false);

		OAuth2TokenService tokenService = new XsuaaOAuth2TokenService(restTemplate());
		AuthenticationInformationExtractor authnExtractor = new DefaultAuthenticationInformationExtractor(AuthenticationMethod.OAUTH2_MUTUAL_TLS);
		return new TokenBrokerResolver(xsuaaServiceConfiguration, cache, tokenService, authnExtractor);
	}


	@Bean
	Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
		TokenAuthenticationConverter converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration);
//		converter.setLocalScopeAsAuthorities(true);
		return converter;
	}

	@Bean
	public RestTemplate restTemplate() throws Exception {
		SSLContext sslContext = SSLContextFactory.getInstance().create(xsuaaServiceConfiguration.getCertificates(), xsuaaServiceConfiguration.getPrivateKey());

		SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext);

		CloseableHttpClient httpClient = HttpClients.custom()
				.setSSLContext(sslContext)
				.setSSLSocketFactory(socketFactory)
				.build();

		HttpComponentsClientHttpRequestFactory clientHttpRequestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);

		return new RestTemplate(clientHttpRequestFactory);
	}
}
