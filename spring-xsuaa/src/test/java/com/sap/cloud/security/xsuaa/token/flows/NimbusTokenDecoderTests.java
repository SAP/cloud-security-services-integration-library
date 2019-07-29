package com.sap.cloud.security.xsuaa.token.flows;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.Test;

import com.sap.cloud.security.xsuaa.token.flows.NimbusTokenDecoder;
import com.sap.cloud.security.xsuaa.token.flows.VariableKeySetUriTokenDecoder;

public class NimbusTokenDecoderTests {

	@Test
	public void test_constructor() {
		new NimbusTokenDecoder();
	}

	@Test
	public void test_decode_throws_ifNoKeySetUriWasSet() {
		VariableKeySetUriTokenDecoder tokenDecoder = new NimbusTokenDecoder();

		assertThatThrownBy(() -> {
			tokenDecoder.decode("abced");
		}).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("Make sure setJwksUri() is called before calling decode()");
	}
}
