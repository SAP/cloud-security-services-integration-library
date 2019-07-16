package com.sap.cloud.security.xsuaa.token;

import com.sap.cloud.security.xsuaa.extractor.AuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.extractor.DefaultAuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.extractor.LocalAuthoritiesExtractor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import org.springframework.util.Assert;

/**
 * An authentication converter that removes the ugly application id prefix (e.g.
 * my-application-demo!t1229) from the scopes in the JWT.
 *
 */
public class TokenAuthenticationConverter extends AbstractAuthenticationConverter{


	public TokenAuthenticationConverter(AuthoritiesExtractor authoritiesExtractor) {
		super(authoritiesExtractor);
	}

	public TokenAuthenticationConverter(String appId) {
		super(appId);
	}

	public TokenAuthenticationConverter(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		super(xsuaaServiceConfiguration);
	}

	@Override
	public AbstractAuthenticationToken convert(Jwt jwt) {
		return new AuthenticationToken(jwt, authoritiesExtractor.getAuthorities(new XsuaaToken(jwt)));
	}

	/**
	 * This method allows to overwrite the default behavior of the
	 * {@link Token#getAuthorities()} implementation. Creates a new converter with a
	 * new {@link LocalAuthoritiesExtractor}
	 *
	 * @param extractLocalScopesOnly
	 *            true when {@link Token#getAuthorities()} should only extract local
	 *            scopes. Local scopes means that non-application specific scopes
	 *            are filtered out and scopes are returned without appId prefix,
	 *            e.g. "Display".
	 */
	public void setLocalScopeAsAuthorities(boolean extractLocalScopesOnly) {
		if (extractLocalScopesOnly) {
			Assert.state(appId != null,
					"For local Scope extraction 'appId' must be provided to `TokenAuthenticationConverter`");
			authoritiesExtractor = new LocalAuthoritiesExtractor(appId);
		} else {
			authoritiesExtractor = new DefaultAuthoritiesExtractor();
		}
	}

}