package com.sap.cloud.security.config;

import javax.annotation.Nullable;
import java.io.File;
import java.util.Properties;

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
    File[] extractXsuaaBindingFiles(File[] bindings);

    Properties getK8sXsuaaServiceProperties(File [] bindingFiles);
}
