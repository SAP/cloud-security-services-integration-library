package com.sap.cloud.security.xsuaa.token;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.extractor.AuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.extractor.DefaultAuthoritiesExtractor;

/**
 * An authentication converter that sets a OAuth2Authentication object.
 * Required to keep compatibility with UAA.
 */
public abstract class AbstractAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

	protected AuthoritiesExtractor authoritiesExtractor;
	protected String appId;

	/**
	 * Creates a new converter with the given {@link AuthoritiesExtractor}.
	 *
	 * @param authoritiesExtractor
	 *            - the extractor used to turn Jwt scopes into Spring Security
	 *            authorities.
	 */
	public AbstractAuthenticationConverter(AuthoritiesExtractor authoritiesExtractor) {
		this.authoritiesExtractor = authoritiesExtractor;
	}

	/**
	 * Creates a new converter with a new {@link DefaultAuthoritiesExtractor}
	 * instance as default authorities extractor.
	 *
	 * @param appId
	 *            e.g. myXsAppname!t123
	 */
	public AbstractAuthenticationConverter(String appId) {
		authoritiesExtractor = new DefaultAuthoritiesExtractor();
		this.appId = appId;
	}

	/**
	 * Creates a new converter with a new {@link DefaultAuthoritiesExtractor}
	 * instance as default authorities extractor.
	 *
	 * @param xsuaaServiceConfiguration
	 *            the xsuaa configuration
	 */
	public AbstractAuthenticationConverter(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		this(xsuaaServiceConfiguration.getAppId());
	}
}