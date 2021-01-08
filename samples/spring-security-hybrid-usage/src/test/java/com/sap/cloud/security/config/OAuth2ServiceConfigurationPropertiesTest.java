package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.config.cf.CFConstants.XSUAA;
import com.sap.cloud.security.token.TokenClaims;
import org.junit.jupiter.api.Test;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static org.junit.jupiter.api.Assertions.*;

class OAuth2ServiceConfigurationPropertiesTest {
    OAuth2ServiceConfigurationProperties cutIas = new OAuth2ServiceConfigurationProperties(Service.IAS);
    OAuth2ServiceConfigurationProperties cutXsuaa = new OAuth2ServiceConfigurationProperties(Service.XSUAA);
    private static final String ANY_VALUE = "anyValue";

    @Test
    void setGetClientId() {
        cutIas.setClientId(ANY_VALUE);
        assertEquals(cutIas.getClientId(), ANY_VALUE);
        assertTrue(cutIas.hasProperty(CFConstants.CLIENT_ID));
        assertEquals(cutIas.getProperty(CFConstants.CLIENT_ID), ANY_VALUE);

        cutXsuaa.setClientId(ANY_VALUE);
        assertEquals(cutXsuaa.getClientId(), ANY_VALUE);
        assertTrue(cutXsuaa.hasProperty(CFConstants.CLIENT_ID));
        assertEquals(cutXsuaa.getProperty(CFConstants.CLIENT_ID), ANY_VALUE);
    }


    @Test
    void setGetClientSecret() {
        cutIas.setClientSecret(ANY_VALUE);
        assertEquals(cutIas.getClientSecret(), ANY_VALUE);
        assertTrue(cutIas.hasProperty(CLIENT_SECRET));
        assertEquals(cutIas.getProperty(CLIENT_SECRET), ANY_VALUE);

        cutXsuaa.setClientSecret(ANY_VALUE);
        assertEquals(cutXsuaa.getClientSecret(), ANY_VALUE);
        assertTrue(cutXsuaa.hasProperty(CLIENT_SECRET));
        assertEquals(cutXsuaa.getProperty(CLIENT_SECRET), ANY_VALUE);
    }

    @Test
    void setGetUrl() {
        cutIas.setUrl(ANY_VALUE);
        assertEquals(cutIas.getUrl().toString(), ANY_VALUE);
        assertTrue(cutIas.hasProperty(URL));
        assertEquals(cutIas.getProperty(URL), ANY_VALUE);

        cutXsuaa.setUrl(ANY_VALUE);
        assertEquals(cutXsuaa.getUrl().toString(), ANY_VALUE);
        assertTrue(cutXsuaa.hasProperty(URL));
        assertEquals(cutXsuaa.getProperty(URL), ANY_VALUE);
    }

    @Test
    void getProperties() {
        cutIas.setClientId(ANY_VALUE);
        cutIas.setClientSecret(ANY_VALUE);
        assertEquals(cutIas.getProperties().get(CLIENT_ID), ANY_VALUE);
        assertEquals(cutIas.getProperties().get(CLIENT_SECRET), ANY_VALUE);
        assertNull(cutIas.getProperties().get(URL));
    }

    @Test
    void setGetService() {
        assertEquals(cutIas.getService(), Service.IAS);
        assertEquals(cutXsuaa.getService(), Service.XSUAA);
    }

    @Test
    void setGetUaaDomain() {
        cutXsuaa.setUaaDomain(ANY_VALUE);
        assertTrue(cutXsuaa.hasProperty(XSUAA.UAA_DOMAIN));
        assertEquals(cutXsuaa.getProperty(XSUAA.UAA_DOMAIN), ANY_VALUE);
    }

    @Test
    void setGetXsAppName() {
        cutXsuaa.setXsAppName(ANY_VALUE);
        assertTrue(cutXsuaa.hasProperty(XSUAA.APP_ID));
        assertEquals(cutXsuaa.getProperty(XSUAA.APP_ID), ANY_VALUE);
    }

    @Test
    void setGetVerificationKey() {
        cutXsuaa.setVerificationKey(ANY_VALUE);
        assertTrue(cutXsuaa.hasProperty(XSUAA.VERIFICATION_KEY));
        assertEquals(cutXsuaa.getProperty(XSUAA.VERIFICATION_KEY), ANY_VALUE);
    }

    @Test
    void isLegacyMode() {
        assertFalse(cutXsuaa.isLegacyMode());
    }

    @Test
    void setGetConfiguration() {
        assertEquals(cutIas.getConfiguration(), cutIas.getConfiguration());
        assertNotEquals(cutIas.getConfiguration(), cutXsuaa.getConfiguration());
    }
}