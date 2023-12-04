package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.token.Token;

public interface XsuaaJkuFactory {
    String create(Token token);
}
