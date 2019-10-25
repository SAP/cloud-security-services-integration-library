package com.sap.cloud.security.token.jwt;

public interface DecodedJwt {

	String getHeader();

	String getPayload();

	String getSignature();
}
