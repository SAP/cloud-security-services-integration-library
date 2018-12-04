package com.sap.cloud.security.xsuaa.token.authentication;

import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

public class XsuaaJwtDecoderBuilder {

	private XsuaaServiceConfiguration configuration;
	int decoderCacheValidity = 900;
	int decoderCacheSize = 100;

	/**
	 * Utility for building a JWT decoder configuration
	 * @param configuration
	 */
	public XsuaaJwtDecoderBuilder(XsuaaServiceConfiguration configuration) {
		this.configuration = configuration;
	}

	/**
	 * Assemble a JwtDecoder
	 * @return
	 */
	public JwtDecoder build() {
		return new XsuaaJwtDecoder(configuration, decoderCacheValidity, decoderCacheSize);
	}

	/**
	 * Decoders cache the signing keys. Set the cache time.
	 * Default: 900 seconds
	 * @param timeInSeconds
	 * @return
	 */
	public XsuaaJwtDecoderBuilder withDecoderCacheTime(int timeInSeconds)
	{
		this.decoderCacheValidity = timeInSeconds;
		return this;
	}
	/**
	 * Determine size of cached decoder.
	 * Mainly relevant for multi tenant applications.
	 * Default:100
	 * @param size
	 * @return
	 */
	public XsuaaJwtDecoderBuilder withDecoderCacheSize(int size)
	{
		this.decoderCacheSize = size;
		return this;
	}
	
}
