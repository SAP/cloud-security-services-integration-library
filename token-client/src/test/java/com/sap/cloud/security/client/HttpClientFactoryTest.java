/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sap.cloud.security.config.ClientCredentials;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Test;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

public class HttpClientFactoryTest {

	@Test
	public void create() {
		ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
		Logger logger = (Logger) LoggerFactory.getLogger(HttpClientFactory.class);
		listAppender.start();
		logger.addAppender(listAppender);

		CloseableHttpClient cut = HttpClientFactory.create(new ClientCredentials("clientId", "secret"));
		assertNotNull(cut);

		// Assert that custom HttpClientFactory factory has a priority over default
		// com.sap.cloud.security.client.DefaultHttpClientFactory
		assertFalse(cut.getClass().getName().contains("InternalHttpClient"));

		assertThat(listAppender.list.get(1).getLevel()).isEqualTo(Level.ERROR);
		assertThat(listAppender.list.get(1).getMessage()).contains("More than 1");
	}

}