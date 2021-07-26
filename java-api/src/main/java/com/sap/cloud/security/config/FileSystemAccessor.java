package com.sap.cloud.security.config;

import javax.annotation.Nullable;
import java.io.File;

/**
 * The interface for K8s File system access.
 */
public interface FileSystemAccessor {


    /**
     * Gets all bound Xsuaa service instances
     *
     * @return the array of files
     */
    @Nullable
    File[] getXsuaaBindings();

    /**
     * Gets all bound IAS service instances
     *
     * @return the array of files
     */
    @Nullable
    File[] getIasBindings();

    /**
     * Extracts xsuaa binding properties from a single binding.
     *
     * @param bindings the service instance bindings
     * @return the file array of service configuration properties
     */
    @Nullable
    File[] extractXsuaaBindingProperties(File[] bindings);
}
