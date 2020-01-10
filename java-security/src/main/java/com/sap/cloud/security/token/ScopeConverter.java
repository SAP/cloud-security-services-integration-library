package com.sap.cloud.security.token;

import java.util.List;

public interface ScopeConverter {
	List<String> convert(List<String> scopes);
}
