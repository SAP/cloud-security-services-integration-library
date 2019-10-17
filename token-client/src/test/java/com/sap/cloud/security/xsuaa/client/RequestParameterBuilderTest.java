package com.sap.cloud.security.xsuaa.client;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class RequestParameterBuilderTest {

	RequestParameterBuilder cut = new RequestParameterBuilder();

	@Test
	public void withParameter() {
		cut.withParameter("new_parameter", "value");
		assertThat(cut.buildAsMap().get("new_parameter"), is("value"));
	}

}
