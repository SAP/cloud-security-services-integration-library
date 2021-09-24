package com.sap.cloud.security.spring.tmp;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.EnvironmentProvider;

public class CustomEnvironmentProvider implements EnvironmentProvider {

    @Override
    public Environment getCurrent() {
        return null;
    }
}
