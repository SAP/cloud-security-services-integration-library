package com.sap.cloud.security.token.validation;

public interface XsuaaJkuFactory {
    String create(String token);
}
