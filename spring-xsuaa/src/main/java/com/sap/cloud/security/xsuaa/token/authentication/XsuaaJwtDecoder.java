package com.sap.cloud.security.xsuaa.token.authentication;

import java.text.ParseException;
import java.util.concurrent.TimeUnit;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

import net.minidev.json.JSONObject;

public class XsuaaJwtDecoder implements JwtDecoder {

	Cache<String, JwtDecoder> cache;
	private XsuaaServiceConfiguration xsuaaServiceConfiguration;

	XsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration, int cacheValidity, int cacheSize) {
		cache = Caffeine.newBuilder().expireAfterWrite(5, TimeUnit.SECONDS).maximumSize(cacheSize).build();
		this.xsuaaServiceConfiguration = xsuaaServiceConfiguration;
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		try {
			JWT jwt = JWTParser.parse(token);
			String subdomain = getSubdomain(jwt);

			String zid = jwt.getJWTClaimsSet().getStringClaim("zid");
			JwtDecoder decoder = cache.get(subdomain, k -> this.getDecoder(zid, subdomain));
			return decoder.decode(token);
		} catch (ParseException ex) {
			throw new JwtException("Error initializing JWT  decoder:" + ex.getMessage());
		}
	}

	private JwtDecoder getDecoder(String zid, String subdomain) {
		String url = xsuaaServiceConfiguration.getTokenKeyUrl(zid, subdomain);
		NimbusJwtDecoderJwkSupport decoder = new NimbusJwtDecoderJwkSupport(url);
		OAuth2TokenValidator<Jwt> validators = new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(), new XsuaaAudienceValidator(xsuaaServiceConfiguration));
		decoder.setJwtValidator(validators);
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
