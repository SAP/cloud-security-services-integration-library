/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import com.sap.cloud.security.xsuaa.extractor.AuthenticationMethod;
import com.sap.cloud.security.xsuaa.extractor.DefaultAuthenticationInformationExtractor;
import com.sap.cloud.security.xsuaa.extractor.TokenBrokerResolver;
import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cache.Cache;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.web.client.RestOperations;

import java.util.concurrent.TimeUnit;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	private static final Logger LOGGER = LoggerFactory.getLogger(SecurityConfiguration.class);

	@Autowired
	XsuaaServiceConfiguration xsuaaServiceConfiguration;

	@Autowired
	RestOperations xsuaaMtlsRestOperations;

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		//enforce browser login popup with basic authentication
		BasicAuthenticationEntryPoint authEntryPoint = new BasicAuthenticationEntryPoint();
		authEntryPoint.setRealmName("spring-security-basic-auth");

		// @formatter:off
		http.authorizeRequests()
				.antMatchers("/hello-token").hasAuthority("Display")
				.antMatchers("/health").permitAll()
				.anyRequest().denyAll()
			.and()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and().exceptionHandling().authenticationEntryPoint(authEntryPoint).and()
				.oauth2ResourceServer()
				.bearerTokenResolver(getTokenBrokerResolver())
				.jwt()
				.jwtAuthenticationConverter(jwtAuthenticationConverter());

		// @formatter:on
	}

	BearerTokenResolver getTokenBrokerResolver() {
		Cache cache = new CaffeineCache("token",
				Caffeine.newBuilder()
						.expireAfterWrite(15, TimeUnit.MINUTES)
						.maximumSize(100).build(), false);

		return new TokenBrokerResolver(xsuaaServiceConfiguration, cache,
				new XsuaaOAuth2TokenService(xsuaaMtlsRestOperations),
				new DefaultAuthenticationInformationExtractor(AuthenticationMethod.BASIC));
	}


	@Bean
	Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
		TokenAuthenticationConverter converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration);
		converter.setLocalScopeAsAuthorities(true);
		return converter;
	}

	@Bean
	public XsuaaServiceConfiguration xsuaaServiceConfiguration() {
		LOGGER.info("auto-configures XsuaaServiceConfigurationK8s");
		return new XsuaaServiceConfigurationK8s();
	}

	@Configuration
	@ConfigurationProperties
	public class XsuaaServiceConfigurationK8s implements XsuaaServiceConfiguration {

		private String clientId;

		private String clientSecret;

		private String url;

		private String uaaDomain;

		private String identityZoneId;

		private String appid;

		private String privateKey;

		private String certificate;

		private String verificationKey;

		private String credentialType;

		private String certUrl;

		@Override
		public String getUaaUrl() {
			LOGGER.info("uaa url: {}", url);
			return url;
		}

		@Override
		public String getAppId() {
			LOGGER.info("app id: {}", appid);
			return appid;
		}

		@Override
		public String getUaaDomain() {
			LOGGER.info("uaa domain: {}", uaaDomain);
			return uaaDomain;
		}

		@Override
		public String getVerificationKey() {
			return verificationKey;
		}

		@Override
		public String getClientId() {
			LOGGER.info("clientid: {}", clientId);
			return clientId;
		}

		@Override
		public String getClientSecret() {
			LOGGER.info("client secret: {}", clientSecret);
			return clientSecret;
		}

		public void setClientId(String clientId) {
			this.clientId = clientId;
		}

		public void setClientSecret(String clientSecret) {
			this.clientSecret = clientSecret;
		}

		public void setUrl(String url) {
			this.url = url;
		}

		public void setUaaDomain(String uaadomain) {
			this.uaaDomain = uaadomain;
		}

		public void setIdentityZoneId(String identityZoneId) {
			this.identityZoneId = identityZoneId;
		}

		public void setXsappname(String xsappname) {
			this.appid = xsappname;
		}

		public void setPrivateKey(String privateKey) {
			this.privateKey = privateKey;
		}

		public void setCertificate(String certificate) {
			this.certificate = certificate;
		}

		public void setVerificationKey(String verificationKey) {
			this.verificationKey = verificationKey;
		}

		public void setCredentialType(String credentialType) {
			this.credentialType = credentialType;
		}

		public void setCertUrl(String certUrl) {
			this.certUrl = certUrl;
		}
	}

}
