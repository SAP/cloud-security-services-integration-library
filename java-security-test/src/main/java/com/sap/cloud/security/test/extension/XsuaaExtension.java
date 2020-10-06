package com.sap.cloud.security.test.extension;

import com.sap.cloud.security.config.Service;

public class XsuaaExtension extends SecurityTestExtension {

	public XsuaaExtension() {
		super(Service.XSUAA);
	}
}
