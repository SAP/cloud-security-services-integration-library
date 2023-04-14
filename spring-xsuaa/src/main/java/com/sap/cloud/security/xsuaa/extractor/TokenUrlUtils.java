/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p> 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;

/**
 * @deprecated in favor of
 *             {@link com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider}.
 *             Will be deleted with version 3.0.0.
 */
@Deprecated
final class TokenUrlUtils {

	private final static Logger logger = LoggerFactory.getLogger(TokenUrlUtils.class);

	private TokenUrlUtils() {
	}

	/**
	 * Retrieves the URL for the token request
	 * <p>
	 *
	 * @param endpoint
	 *            endpoint
	 * @param uaaUrl
	 *            UAA-URL from Xsuaa Service binding
	 * @param uaaDomain
	 *            UAA-Domain from Xsuaa Service binding
	 * @param uaaSubDomain
	 *            UAA-Subdomain in case of Multi tenancy
	 *
	 * @return token request URL
	 */
	static String getMultiTenancyUrl(final String endpoint, final String uaaUrl, final String uaaDomain,
			final String uaaSubDomain) {
		Assert.notNull(endpoint, "Endpoint must not be null");
		Assert.notNull(uaaUrl, "UAA URL must not be null");
		Assert.notNull(uaaDomain, "UAA Domain must not be null");
		Assert.notNull(uaaSubDomain, "UAA Subdomain must not be null");

		return TokenUrlUtils.getUrl(endpoint, uaaUrl, uaaDomain, uaaSubDomain);
	}

	/**
	 * Retrieves the URL for the token request
	 * <p>
	 *
	 * @param endpoint
	 *            endpoint
	 * @param uaaUrl
	 *            UAA-URL from Xsuaa Service binding
	 * @param uaaDomain
	 *            UAA-URL from Xsuaa Service binding
	 *
	 * @return token request URL
	 */
	static String getOauthTokenUrl(final String endpoint, final String uaaUrl, final String uaaDomain) {
		Assert.notNull(endpoint, "Endpoint must not be null");
		Assert.notNull(uaaUrl, "UAA URL must not be null");
		Assert.notNull(uaaDomain, "UAA Domain must not be null");
		return uaaUrl + endpoint;
	}

	private static String getUrl(final String endpoint, final String uaaUrl, final String uaaDomain,
			String tenantSubDomain) {

		String tenantUaaDomain = tenantSubDomain + "." + uaaDomain;

		URI uri = URI.create(uaaUrl);

		String protocol = uri.getScheme();

		String tenantTokenUrl = String.format("%s://%s", protocol, tenantUaaDomain + endpoint);
		logger.debug("Created tenant token URL {}.", tenantTokenUrl);
		return tenantTokenUrl;
	}

}
