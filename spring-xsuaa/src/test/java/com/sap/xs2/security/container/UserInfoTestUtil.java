package com.sap.xs2.security.container;

import java.io.IOException;
import java.nio.charset.Charset;

import org.apache.commons.io.IOUtils;
import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.test.JwtGenerator;

public class UserInfoTestUtil {

	public static UserInfo createFromTemplate(String pathToTemplate, String appName) throws IOException {
		Jwt jwt = new JwtGenerator().createFromTemplate(pathToTemplate);
		return new UserInfo(jwt, appName);
	}

	public static UserInfo createFromJwtFile(String pathToJwt, String appName) throws IOException {
		String token = IOUtils.resourceToString(pathToJwt, Charset.forName("UTF-8"));
		Jwt jwt = JwtGenerator.convertTokenToOAuthJwt(token);
		return new UserInfo(jwt, appName);
	}
}