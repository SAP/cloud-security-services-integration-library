package com.sap.cloud.security.xsuaa.util;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

public class UriUtil {

	private static final Logger logger = LoggerFactory.getLogger(UriUtil.class);

	/**
	 * Utility method that replaces the subdomain of the URI with the given
	 * subdomain.
	 *
	 * @param uri
	 *            the URI to be replaced.
	 * @param subdomain
	 *            of the tenant.
	 * @return the URI with the replaced subdomain or the passed URI in case a
	 *         replacement was not possible.
	 */
	public static URI replaceSubdomain(@Nonnull URI uri, @Nullable String subdomain) {
		assertNotNull(uri, "the uri parameter must not be null");
		if (hasText(subdomain) && hasSubdomain(uri)) {
			String newHost = subdomain + uri.getHost().substring(uri.getHost().indexOf('.'));
			try {
				return uri.resolve(new URI(uri.getScheme(), uri.getUserInfo(), newHost, uri.getPort(), uri.getPath(),
						uri.getQuery(), uri.getFragment()));
			} catch (URISyntaxException e) {
				logger.error("Could not replace subdomain {} in given uri {}", subdomain, uri);
				throw new IllegalArgumentException(e);
			}
		}
		logger.info("the subdomain of the URI '{}' is not replaced by subdomain '{}'", uri, subdomain);
		return uri;
	}

	/**
	 * Utility method that sets the "cert" in the URI host.
	 *
	 * @param uri
	 *            the URI to be replaced.
	 * @return the URI with the "cert" domain.
	 */
	public static URI setCertDomain(URI uri) {
		assertNotNull(uri, "the uri parameter must not be null");
		String newHost = uri.getHost();
		try {
			if (uri.getHost().contains(".authentication.")) {
				newHost = newHost.replace(".authentication.", ".authentication.cert.");
			}
			return new URI(uri.getScheme(), uri.getUserInfo(), newHost, uri.getPort(),
					uri.getPath(), uri.getQuery(), uri.getFragment());
		} catch (URISyntaxException e) {
			logger.error("Could not set cert domain in given uri {}", uri);
			throw new IllegalStateException(e);
		}
	}

	private static boolean hasSubdomain(URI uri) {
		return uri.getHost().contains(".");
	}

	private static boolean hasText(String string) {
		return Optional.ofNullable(string).filter(str -> !str.trim().isEmpty()).isPresent();
	}

	/**
	 * Utility method that expands the path of the URI.
	 *
	 * @param uri
	 *            the URI to be replaced.
	 * @param pathToAppend
	 *            the path to append.
	 * @return the URI with the path.
	 */
	public static URI expandPath(URI uri, String pathToAppend) {
		assertNotNull(uri, "the uri parameter must not be null");
		assertHasText(pathToAppend, "the path parameter must not be null or ''");
		try {
			String newPath = uri.getPath() + pathToAppend;
			return new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(),
					replaceDoubleSlashes(newPath), uri.getQuery(), uri.getFragment());
		} catch (URISyntaxException e) {
			logger.error("Could not set path {} in given uri {}", pathToAppend, uri);
			throw new IllegalStateException(e);
		}
	}

	private static String replaceDoubleSlashes(String newPath) {
		return newPath.replaceAll("//", "/");
	}
}
