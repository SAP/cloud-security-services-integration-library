package com.sap.cloud.security.config;

import java.util.Properties;

/**
 * The interface for service configuration access.
 */
public interface ServiceConfigurationAccessor {

    /**
     * Gets XSUAA service instance properties.
     *
     * @return the XSUAA service properties
     */
    Properties getXsuaaServiceProperties();

    /**
     * Gets IAS service instance properties.
     *
     * @return the IAS service properties
     */
    Properties getIasServiceProperties();

}
