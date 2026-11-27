/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.util;

import com.sap.cloud.security.xsuaa.Assertions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import java.util.regex.Pattern;

public class UriUtil {

	private static final Logger logger = LoggerFactory.getLogger(UriUtil.class);
	private static final Pattern SUBDOMAIN_PATTERN = Pattern.compile("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?");

	private UriUtil() {
		// use static methods
	}

	/**
	 * Utility method that replaces the subdomain of the URI with the given subdomain.
	 *
	 * @param uri
	 * 		the URI to be replaced.
	 * @param subdomain
	 * 		of the tenant, as a single RFC 1123 DNS label (1-63 ASCII letters, digits or hyphens,
	 * 		with no leading or trailing hyphen). Null, empty and blank values leave the URI unchanged.
	 * @return the URI with the replaced subdomain or the passed URI in case a replacement was not possible.
	 * @throws IllegalArgumentException
	 * 		if a nonblank subdomain is not a single RFC 1123 DNS label.
	 */
	public static URI replaceSubdomain(@Nonnull URI uri, @Nullable String subdomain) {
		Assertions.assertNotNull(uri, "the uri parameter must not be null");
		if (hasText(subdomain) && !SUBDOMAIN_PATTERN.matcher(subdomain).matches()) {
			throw new IllegalArgumentException("Subdomain must be a single RFC 1123 DNS label");
		}
		if (hasText(subdomain) && hasSubdomain(uri)) {
			String newHost = subdomain + uri.getHost().substring(uri.getHost().indexOf('.'));
			try {
				return uri.resolve(new URI(uri.getScheme(), uri.getUserInfo(), newHost, uri.getPort(), uri.getPath(),
						uri.getQuery(), uri.getFragment()));
			} catch (URISyntaxException e) {
				logger.error("Could not replace subdomain in given uri {}", uri);
				throw new IllegalArgumentException(e);
			}
		}
		logger.debug("the subdomain of the URI {} was not replaced by subdomain", uri);
		return uri;
	}

	private static boolean hasSubdomain(URI uri) {
		return uri.isAbsolute() && uri.getHost() != null && uri.getHost().contains(".");
	}

	private static boolean hasText(String string) {
		return Optional.ofNullable(string).filter(str -> !str.trim().isEmpty()).isPresent();
	}

	/**
	 * Utility method that expands the path of the URI.
	 *
	 * @param baseUri
	 * 		the URI to be replaced.
	 * @param pathToAppend
	 * 		the path to append.
	 * @return the URI with the path.
	 */
	// TODO rename to getUriWithPathAppended
	@Nonnull
	public static URI expandPath(@Nonnull URI baseUri, String pathToAppend) {
		Assertions.assertNotNull(baseUri, "the baseUri parameter must not be null");
		try {
			String newPath = baseUri.getPath() + pathToAppend;
			return new URI(baseUri.getScheme(), baseUri.getUserInfo(), baseUri.getHost(), baseUri.getPort(),
					replaceDoubleSlashes(newPath), baseUri.getQuery(), baseUri.getFragment());
		} catch (URISyntaxException e) {
			throw new IllegalStateException(e);
		}
	}

	@Nonnull
	private static String replaceDoubleSlashes(String newPath) {
		return newPath.replace("//", "/");
	}
}
