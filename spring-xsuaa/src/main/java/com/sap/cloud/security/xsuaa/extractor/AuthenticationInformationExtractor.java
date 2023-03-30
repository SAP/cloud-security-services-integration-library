/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import jakarta.servlet.http.HttpServletRequest;

import java.util.List;
import java.util.Optional;

public interface AuthenticationInformationExtractor {

	/**
	 * Get subdomain from configuration or request
	 * 
	 * @param request
	 *            HTTP request
	 * @return Client Subdomain
	 */
	Optional<String> getSubdomain(HttpServletRequest request);

	/**
	 * Get subdomain from configuration
	 * 
	 * @return Client Subdomain
	 */
	Optional<String> getSubdomain();

	/**
	 * Possibility to return AuthMethods dynamically depending on request
	 * 
	 * @param request
	 *            HTTP request
	 * @return AuthenticationMethods Configured Authentication Methods
	 */
	List<AuthenticationMethod> getAuthenticationMethods(HttpServletRequest request);

}
