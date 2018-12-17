/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package testservice.api.basic;

import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sap.xs2.security.container.UserInfo;
import com.sap.xs2.security.container.UserInfoException;
import com.sap.xs2.security.container.XSTokenRequestImpl;
import com.sap.xsa.security.container.XSTokenRequest;

@RestController
public class TestController {

	@Value("${mockxsuaaserver.url}")
	String mockServerUrl;

	@GetMapping("/")
	public String index(@AuthenticationPrincipal Jwt jwt) {
		return String.format("Hello, %s!", jwt.getSubject());
	}

	@GetMapping("/user")
	public String message(@AuthenticationPrincipal UserInfo token) throws UserInfoException {
		try {
			return "user:" + token.getLogonName();
		} catch (UserInfoException ex) {
			return "client:" + token.getClientId();
		}
	}

	@GetMapping("/scope")
	public void checkScope(@AuthenticationPrincipal UserInfo token) throws UserInfoException {
		Assert.assertTrue(token.checkScope("openid"));
		Assert.assertTrue(token.checkLocalScope("Display"));
		Assert.assertFalse(token.checkLocalScope("Other"));
	}

	@GetMapping("/requesttoken")
	public String requestToken(@AuthenticationPrincipal UserInfo token) throws UserInfoException, URISyntaxException {
		XSTokenRequestImpl tokenRequest = new XSTokenRequestImpl(mockServerUrl);
		tokenRequest.setClientId("c1").setClientSecret("s1").setType(XSTokenRequest.TYPE_CLIENT_CREDENTIALS_TOKEN);
		Map<String, String> azMape = new HashMap<>();
		azMape.put("a", "b");
		azMape.put("c", "d");
		tokenRequest.setAdditionalAuthorizationAttributes(azMape);
		String newToken = token.requestToken(tokenRequest);
		return newToken;
	}
}
