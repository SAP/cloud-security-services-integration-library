package com.sap.cloud.security.spring.token;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.spring.config.OAuth2ServiceConfigurationProperties;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.spring.token.authentication.XsuaaTokenAuthorizationConverter;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;

public class ReactiveTokenAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    /*
    	final TokenAuthenticationConverter converter;

	public ReactiveTokenAuthenticationConverter(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		this.converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration.getAppId());
	}
     */

    final XsuaaTokenAuthorizationConverter converter;

    public ReactiveTokenAuthenticationConverter(OAuth2ServiceConfiguration configuration) {
        this.converter = new XsuaaTokenAuthorizationConverter(configuration.getProperty(ServiceConstants.XSUAA.APP_ID));
    }


    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        return converter.convert(jwt);
    }

}
