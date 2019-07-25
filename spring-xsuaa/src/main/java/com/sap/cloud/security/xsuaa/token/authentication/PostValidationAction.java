package com.sap.cloud.security.xsuaa.token.authentication;

import org.springframework.security.oauth2.jwt.Jwt;

public interface PostValidationAction {

	void perform(Jwt token);
}
