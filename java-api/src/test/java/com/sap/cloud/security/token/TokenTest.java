/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.Test;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.*;

public class TokenTest {

	@Test
	public void create() {
		ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
		Logger logger = (Logger) LoggerFactory.getLogger(Token.class);
		listAppender.start();
		logger.addAppender(listAppender);

		Token cut = Token.create("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
		assertNotNull(cut);

		cut = Token.create("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
		assertNotNull(cut);

		// Assert that custom Token factory has a priority over default
		// com.sap.cloud.security.servlet.HybridTokenFactory
		assertFalse(cut.getClass().getName().contains("AccessToken"));

		assertThat(listAppender.list.get(1).getLevel()).isEqualTo(Level.ERROR);
		assertThat(listAppender.list.get(1).getMessage()).contains("More than 1 service provider found");
	}

}
