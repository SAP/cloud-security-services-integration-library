/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import java.io.Serializable;
import java.util.Collection;
import java.util.Set;

public interface ScopeConverter extends Serializable {
	Set<String> convert(Collection<String> scopes);
}
