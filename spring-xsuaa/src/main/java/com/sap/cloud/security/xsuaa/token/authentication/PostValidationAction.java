/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token.authentication;

import org.springframework.security.oauth2.jwt.Jwt;

public interface PostValidationAction {

	void perform(Jwt token);
}
