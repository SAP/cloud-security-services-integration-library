package com.sap.cloud.security.token;

import java.util.List;

public interface TokenScopeConverter {
    List<String> convert(List<String> scopes);
}
