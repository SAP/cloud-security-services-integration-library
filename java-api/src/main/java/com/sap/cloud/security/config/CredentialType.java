/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
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
	public static CredentialType from(String claimValue) {
		for (CredentialType credentialType : values()) {
			if (credentialType.typeName.equals(claimValue)) {
				return credentialType;
			}
		}
		return null;
	}

}
