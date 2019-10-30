package com.sap.cloud.security.xsuaa.jwt;

import java.util.Map;

public interface DecodedJwt {

	String getHeader();

	Map<String, Object> getHeaderMap();

	String getPayload();

	Map<String, Object> getPayloadMap();

	String getSignature();

	String getEncodedToken();
}
