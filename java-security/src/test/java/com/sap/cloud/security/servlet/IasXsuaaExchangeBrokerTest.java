package com.sap.cloud.security.servlet;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class IasXsuaaExchangeBrokerTest {

	@Test
	void doIasToXsuaaXchange_ConfigurationIsNull() {
		IasXsuaaExchangeBroker exchangeBroker = new IasXsuaaExchangeBroker();

		assertThrows(
				IllegalArgumentException.class,
				() -> exchangeBroker.doIasToXsuaaXchange(null, null, null),
				"Service configuration must not be null");
	}
}