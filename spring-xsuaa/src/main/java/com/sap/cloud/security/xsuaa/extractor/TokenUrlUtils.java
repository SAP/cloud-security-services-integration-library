/**
 * 
 */
package com.sap.cloud.security.xsuaa.extractor;

import static org.springframework.util.StringUtils.isEmpty;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Objects;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public final class TokenUrlUtils {

	private final static Log logger = LogFactory.getLog(TokenUrlUtils.class);

	private TokenUrlUtils() {
	}

	/**
	 * Retrieves the URL for the token request
	 * <p>
	 * 
	 * @param endpoint
	 *            endpoint
	 * @param uaaUrl
	 *            UAA-URL from VCAP-Services
	 * @param uaaDomain
	 *            UAA-Domain from VCAP-Services
	 * @param uaaSubDomain
	 *            UAA-Subdomain in case of Multi tenancy
	 * 
	 * @return token request URL
	 */

	public static String getMultiTenancyUrl(final String endpoint, final String uaaUrl, final String uaaDomain,
			final String uaaSubDomain) {
		Objects.requireNonNull(uaaUrl, "URL must not be null");
		Objects.requireNonNull(uaaDomain, "Domain must not be null");
		Objects.requireNonNull(endpoint, "Endpoint must not be null");

		if (uaaSubDomain == null) {
			return uaaUrl + endpoint;
		}
		return TokenUrlUtils.getUrl(endpoint, uaaUrl, uaaDomain, uaaSubDomain);
	}

	public static String getOauthTokenUrl(final String endpoint, final String uaaUrl, final String uaaDomain) {
		return TokenUrlUtils.getMultiTenancyUrl(endpoint, uaaUrl, uaaDomain, null);
	}

	private static String getUrl(final String endpoint, final String uaaUrl, final String uaaDomain,
			String tenantSubDomain) {

		Objects.requireNonNull(uaaUrl, "UAA-URL must not be null");
		Objects.requireNonNull(uaaDomain, "Domain must not be null");
		Objects.requireNonNull(tenantSubDomain, "SubDomain must not be null");
		Objects.requireNonNull(endpoint, "Endpoint must not be null");

		String tenantUaaDomain = tenantSubDomain + "." + uaaDomain;

		URL url;
		try {
			url = new URL(uaaUrl);
		} catch (MalformedURLException e) {
			throw new RuntimeException("Cannot create valid URL from given UAA-Url " + uaaUrl);
		}
		String protocol = url.getProtocol();

		String tenantTokenUrl = String.format("%s://%s", protocol, tenantUaaDomain + endpoint);
		logger.debug("Created tenant token URL " + tenantTokenUrl);
		return tenantTokenUrl;
	}

	public static String getHost(String path) {
		URL url;
		try {
			url = new URL(path);
		} catch (MalformedURLException e) {
			throw new RuntimeException("Cannot create valid URL from given Url " + path);
		}
		return url.getHost();
	}

	public static boolean isUrl(String url) {
		if (isEmpty(url)) {
			return false;
		}
		try {
			new URL(url);
			return true;
		} catch (MalformedURLException e) {
			return false;
		}
	}

}
