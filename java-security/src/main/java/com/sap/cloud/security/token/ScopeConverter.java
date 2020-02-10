package com.sap.cloud.security.token;

import java.util.Collection;
import java.util.Set;

public interface ScopeConverter {
	Set<String> convert(Collection<String> scopes);
}
