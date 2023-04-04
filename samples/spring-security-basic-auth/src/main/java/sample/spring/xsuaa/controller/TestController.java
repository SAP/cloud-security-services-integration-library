/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa.controller;

import com.sap.cloud.security.token.Token;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

	@GetMapping("/mirror-token")
	public Token message(@AuthenticationPrincipal Token token) {
		return token;
	}

	@GetMapping("/health")
	public String checkHealth(){
		return "OK";
	}
}
