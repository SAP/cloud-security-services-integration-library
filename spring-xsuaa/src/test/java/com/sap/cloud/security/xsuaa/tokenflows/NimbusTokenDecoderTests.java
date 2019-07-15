package com.sap.cloud.security.xsuaa.tokenflows;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.Test;

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
        }).isInstanceOf(IllegalStateException.class).hasMessageContaining("Make sure setJwksUri() is called before calling decode()");
    }
}
