package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.client.ClientCertificate;
import com.sap.cloud.security.client.ClientCredentials;
import com.sap.xsa.security.container.ClientIdentity;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.*;

class ClientIdentityTest {
    private static ClientIdentity cut;
    private static ClientIdentity cut2;

    @BeforeAll
    static void init() {
        cut = new ClientCredentials("clientId", "clientSecret");
        cut2 = new ClientCertificate("CERT", "KEY", "clientId");
    }

    @Test
    void getId() {
        assertEquals("clientId", cut.getId());
        assertEquals("clientId", cut2.getId());
    }

    @Test
    void isCertificateBased() {
        assertTrue(cut2.isCertificateBased());
        assertFalse(cut.isCertificateBased());
    }

    @Test
    void getSecret() {
        assertEquals("clientSecret", cut.getSecret());
        assertNull(cut2.getSecret());
    }

    @Test
    void getCertificate() {
        assertNull(cut.getCertificate());
        assertEquals("CERT", cut2.getCertificate());
    }

    @Test
    void getKey() {
        assertNull(cut.getKey());
        assertEquals("KEY", cut2.getKey());
    }

    @ParameterizedTest
    @MethodSource("isValidClientCertificateTestArguments")
    void isValidClientCertificate(String cert, String key, String clientId, boolean expected, Class<IllegalArgumentException> expectedException) {
        if (expectedException != null) {
            assertThatThrownBy(() -> new ClientCertificate(cert, key, clientId)).isExactlyInstanceOf(expectedException);
        } else {
            ClientIdentity invalidCertificate = new ClientCertificate(cert, key, clientId);
            assertThat(invalidCertificate.isValid()).isEqualTo(expected);
        }
    }

    @ParameterizedTest
    @MethodSource("isValidClientCredentialsTestArguments")
    void isValidClientCredentials(String clientId, String clientSecret, boolean expected, Class<IllegalArgumentException> expectedException) {
        if (expectedException != null) {
            assertThatThrownBy(() -> new ClientCredentials(clientId, clientSecret)).isExactlyInstanceOf(expectedException);
        } else {
            ClientIdentity clientCredentials = new ClientCredentials(clientId, clientSecret);
            assertThat(clientCredentials.isValid()).isEqualTo(expected);
        }
    }

    private static Stream<Arguments> isValidClientCredentialsTestArguments() {
        return Stream.of(
                Arguments.of("clientId", "clientSecret", true, null),
                Arguments.of(null, "clientSecret", false, IllegalArgumentException.class),
                Arguments.of("clientId", null, false, IllegalArgumentException.class),
                Arguments.of("clientId", "", false, IllegalArgumentException.class),
                Arguments.of("", "clientSecret", false, IllegalArgumentException.class)

        );
    }

    private static Stream<Arguments> isValidClientCertificateTestArguments() {
        return Stream.of(
                Arguments.of("CERT", "KEY", "clientId", true, null),
                Arguments.of("CERT", "KEY", "", false, null),
                Arguments.of("CERT", "", "clientId", false, null),
                Arguments.of("", "KEY", "clientId", false, null),
                Arguments.of(null, "KEY", "clientId", false, IllegalArgumentException.class),
                Arguments.of("CERT", null, "clientId", false, IllegalArgumentException.class),
                Arguments.of("CERT", "KEY", null, false, IllegalArgumentException.class)
        );
    }
}