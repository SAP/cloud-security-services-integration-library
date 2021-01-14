package com.sap.cloud.security.token;

public interface TokenFactory {

	Token create(String jwtToken, String appId);
}
