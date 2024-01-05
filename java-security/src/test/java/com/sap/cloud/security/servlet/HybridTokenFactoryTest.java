package com.sap.cloud.security.servlet;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sap.cloud.security.token.XsuaaToken;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HybridTokenFactoryTest {

	private ListAppender<ILoggingEvent> logWatcher;
	private HybridTokenFactory cut;

	@BeforeEach
	public void setup() {
		cut = new HybridTokenFactory();
		cut.xsAppId = null;
		cut.xsScopeConverter = null;
		logWatcher = new ListAppender<>();
		logWatcher.start();
		((Logger) LoggerFactory.getLogger(HybridTokenFactory.class)).addAppender(logWatcher);
	}

	@AfterEach
	void teardown() {
		((Logger) LoggerFactory.getLogger(HybridTokenFactory.class)).detachAndStopAllAppenders();
	}

	@Test
	void oneWarningMessageIncaseSecurityConfigIsMissing() throws IOException {
		String jwt = IOUtils.resourceToString("/xsuaaJwtBearerTokenRSA256.txt", UTF_8);
		XsuaaToken token = (XsuaaToken) cut.create(jwt);
		cut.create(jwt);

		assertThat(token.getIssuer()).isEqualTo("http://auth.com");
		assertThrows(IllegalArgumentException.class, () -> token.hasLocalScope("abc"));
		assertThat(logWatcher.list).isNotNull().hasSize(1);
		assertThat(logWatcher.list.get(0).getMessage()).contains("There is no xsuaa service configuration");
	}
}