package com.sap.cloud.security.token;

import java.util.Collection;
import java.util.List;

public interface ScopeConverter {
	List<String> convert(Collection<String> scopes);
}
