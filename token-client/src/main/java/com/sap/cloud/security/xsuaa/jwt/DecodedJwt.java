package com.sap.cloud.security.xsuaa.jwt;

public interface DecodedJwt {

	String getHeader();

	String getPayload();

	String getSignature();
}
