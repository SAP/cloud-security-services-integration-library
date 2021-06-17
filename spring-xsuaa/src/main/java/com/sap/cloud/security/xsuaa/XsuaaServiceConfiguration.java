/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.CredentialType;

import javax.annotation.Nullable;

public interface XsuaaServiceConfiguration {
	/**
	 * Client id of xsuaa service instance
	 * 
	 * @return clientId
	 */
	String getClientId();

	/**
	 * Client secret of xsuaa instance
	 * 
	 * @return client secret
	 */
	String getClientSecret();

	/**
	 * Client Identity of xsuaa instance
	 * 
	 * @return ClientIdentity object
	 */
	default ClientIdentity getClientIdentity() {
		return new ClientCredentials(getClientId(), getClientSecret());
	}

	/**
	 * Base URL of the xsuaa service instance. In multi tenancy scenarios this is
	 * the url where the service instance was created.
	 * 
	 * @return uaa url
	 */
	String getUaaUrl();

	/**
	 * Base certificate URL of the xsuaa service instance.
	 *
	 * @return uaa mTLS url
	 */
	@Nullable
	default String getUaaCertUrl(){ return null; }

	/**
	 * Credential type as defined in "oauth2-configuration" of the xsuaa service
	 * instance security descriptor.
	 *
	 * @return value of credential-type field
	 */
	default CredentialType getCredentialType(){ return null; }

	/**
	 * XS application identifier
	 * 
	 * @return xs application id
	 */
	String getAppId();

	/**
	 * Domain of the xsuaa authentication domain
	 * 
	 * @return uaaDomain
	 */
	String getUaaDomain();

	/**
	 * The pem encoded public key for offline token verification.
	 *
	 * @return the pem encoded verification key
	 */
	@Nullable
	String getVerificationKey();
}