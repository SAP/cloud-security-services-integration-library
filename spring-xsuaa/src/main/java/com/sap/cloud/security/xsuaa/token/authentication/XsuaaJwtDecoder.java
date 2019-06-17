package com.sap.cloud.security.xsuaa.token.authentication;

import java.text.ParseException;
import java.util.concurrent.TimeUnit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import net.minidev.json.JSONObject;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.util.Assert;

public class XsuaaJwtDecoder implements JwtDecoder {

	Cache<String, JwtDecoder> cache;
	private XsuaaServiceConfiguration xsuaaServiceConfiguration;
	private OAuth2TokenValidator<Jwt> tokenValidators;

	XsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration, int cacheValidityInSeconds, int cacheSize,
			OAuth2TokenValidator<Jwt> tokenValidators) {
		cache = Caffeine.newBuilder().expireAfterWrite(cacheValidityInSeconds, TimeUnit.SECONDS).maximumSize(cacheSize)
				.build();
		this.xsuaaServiceConfiguration = xsuaaServiceConfiguration;
		this.tokenValidators = tokenValidators;
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		Assert.notNull(token, "token is required");
		try {
			JWT jwt = JWTParser.parse(token);
			String subdomain = getSubdomain(jwt);

			String zid = jwt.getJWTClaimsSet().getStringClaim("zid");
			JwtDecoder decoder = cache.get(subdomain, k -> this.getDecoder(zid, subdomain));
			return decoder.decode(token);
		} catch (ParseException ex) {
			throw new JwtException("Error initializing JWT decoder:" + ex.getMessage());
		}
	}

	protected JwtDecoder getDecoder(String zid, String subdomain) {
		String url = xsuaaServiceConfiguration.getTokenKeyUrl(zid, subdomain);
		NimbusJwtDecoderJwkSupport decoder = new NimbusJwtDecoderJwkSupport(url);
		decoder.setJwtValidator(tokenValidators);
		return decoder;
	}

	protected String getSubdomain(JWT jwt) throws ParseException {
		String subdomain = "";
		JSONObject extAttr = jwt.getJWTClaimsSet().getJSONObjectClaim("ext_attr");
		if (extAttr != null && extAttr.getAsString("zdn") != null) {
			subdomain = extAttr.getAsString("zdn");
		}
		return subdomain;
	}

}
