package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFEnvironment;
import com.sap.cloud.security.config.k8s.K8sEnvironment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.sap.cloud.security.config.k8s.K8sConstants.KUBERNETES_SERVICE_HOST;

public class DefaultEnvironmentLoader implements EnvironmentLoader {
	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultEnvironmentLoader.class);
	private static Environment currentEnvironment;

	@Override
	public Environment getCurrent() {
		if (currentEnvironment == null) {
			if (isK8sEnv()) {
				LOGGER.debug("K8s environment detected");
				currentEnvironment = K8sEnvironment.getInstance();
			} else {
				LOGGER.debug("CF environment detected");
				currentEnvironment = CFEnvironment.getInstance();
			}
		}
		return currentEnvironment;
	}

	private static boolean isK8sEnv() {
		return System.getenv().get(KUBERNETES_SERVICE_HOST) != null;
	}
}
