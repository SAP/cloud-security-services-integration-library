package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.FileSystemAccessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.File;

/**
 * The type File system accessor.
 */
public class FileSystemAccessorDefault implements FileSystemAccessor {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileSystemAccessorDefault.class);
    private static final String DEFAULT_XSUAA_PATH = "/etc/secrets/sapcp/xsuaa";
    private static final String DEFAULT_IAS_PATH = "/etc/secrets/sapcp/ias";
    private String customXsuaaPath;
    private String customIasPath;


    /**
     * Instantiates a new K8s secrets' files accessor with default paths.
     * IAS - /etc/secrets/sapcp/ias
     * XSUAA - /etc/secrets/sapcp/xsuaa
     */
    public FileSystemAccessorDefault() {
    }


    /**
     * Instantiates a new K8s secrets' files accessor with user defined paths.
     *
     * @param customXsuaaPath the custom xsuaa path
     * @param customIasPath   the custom ias path
     */
    public FileSystemAccessorDefault(@Nullable String customXsuaaPath, @Nullable String customIasPath) {
        this.customXsuaaPath = customXsuaaPath;
        this.customIasPath = customIasPath;
    }


    @Override
    @Nullable
    public File[] getXsuaaBindings(){
        return new File(customXsuaaPath != null ? customXsuaaPath : DEFAULT_XSUAA_PATH).listFiles();
    }

    @Override
    @Nullable
    public File[] getIasBindings(){
        return new File(customIasPath != null ? customIasPath : DEFAULT_IAS_PATH).listFiles();
    }

    @Override
    @Nullable
    public File[] extractXsuaaBindingProperties(File[] bindings){
        if (bindings != null && bindings.length != 0){
            final File binding = bindings[0];
            LOGGER.debug("Found {} k8s secret binding(s). Selecting '{}'", bindings.length, binding.getName());
            return new File(binding.getPath()).listFiles();
        }
        return null;
    }

}
