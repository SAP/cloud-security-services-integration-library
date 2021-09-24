package com.sap.cloud.security.config;

/**
 * TODO
 */
public interface EnvironmentProvider {
    /**
     * Determines the current type of {@link Environment}.
     *
     * @return the current environment
     */
    Environment getCurrent();
}
