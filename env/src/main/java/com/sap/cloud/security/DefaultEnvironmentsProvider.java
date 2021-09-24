package com.sap.cloud.security;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.EnvironmentProvider;
import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.cf.CFEnvironment;
import com.sap.cloud.security.config.k8s.K8sEnvironment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.sap.cloud.security.config.k8s.K8sConstants.KUBERNETES_SERVICE_HOST;

public class DefaultEnvironmentsProvider implements EnvironmentProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(Environments.class);

    @Override
    public Environment getCurrent() {
        if (isK8sEnv()) {
            LOGGER.debug("K8s environment detected");
            return K8sEnvironment.getInstance();
        } else {
            LOGGER.debug("CF environment detected");
            return CFEnvironment.getInstance();
        }
    }

    private static boolean isK8sEnv() {
        return System.getenv().get(KUBERNETES_SERVICE_HOST) != null;
    }
}
