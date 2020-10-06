package com.sap.cloud.security.test.extension;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.SecurityTest;

public class XsuaaExtension extends SecurityTestExtension {

    public XsuaaExtension() {
        super(new SecurityTest(Service.XSUAA));
    }
}
