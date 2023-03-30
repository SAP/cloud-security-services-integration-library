/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.UUID;

/**
 * The Mapped Diagnostic Context helper class.
 */
public final class MDCHelper {

	public static final String CORRELATION_ID = "correlation_id";
	public static final String CORRELATION_HEADER = "X-CorrelationID";
	private static final Logger LOGGER = LoggerFactory.getLogger(MDCHelper.class);

	private MDCHelper() {
	}

	/**
	 * Gets correlation_id from MDC, if it is missing, new correlation_id will be
	 * created.
	 *
	 * @return the string of correlation_id
	 */
	public static String getOrCreateCorrelationId() {
		String correlationId = MDC.get(CORRELATION_ID);
		if (correlationId == null || correlationId.isEmpty()) {
			correlationId = String.valueOf(UUID.randomUUID());
			LOGGER.info("Correlation id (key={}) was not found in the MDC, generating a new one: {}", CORRELATION_ID,
					correlationId);
		} else {
			LOGGER.debug("Correlation id (key={}) from MDC: {}", CORRELATION_ID, correlationId);
		}
		return correlationId;
	}
}
