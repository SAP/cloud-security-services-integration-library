package com.sap.cloud.security.config;

import javax.annotation.Nullable;

/**
 * Constants denoting the credential types of identity OAuth2 configuration
 */
public enum CredentialType {
	X509("x509"), INSTANCE_SECRET("instance-secret"), BINDING_SECRET("binding-secret");

	private final String typeName;

	CredentialType(String typeName) {
		this.typeName = typeName;
	}

	@Override
	public String toString() {
		return typeName;
	}

	@Nullable
	public static CredentialType from(String claimName) {
		for (CredentialType credentialType : values()) {
			if (credentialType.typeName.equals(claimName)) {
				return credentialType;
			}
		}
		return null;
	}

}
