/**
 * 
 */
package com.sap.cloud.security.xsuaa.extractor;

import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

public interface AuthenticationInformationExtractor {

    /**
     * Get subdomain from configuration or request
     * 
     * @param request
     *            HTTP request
     * @return Client Subdomain
     */
    Optional<String> getSubdomain(HttpServletRequest request);

    /**
     * Get subdomain from configuration
     * 
     * @return Client Subdomain
     */
    Optional<String> getSubdomain();

    /**
     * Possibility to return AuthMethods dynamically depending on request
     * 
     * @param request
     *            HTTP request
     * @return AuthenticationMethods Configured Authentication Methods
     */
    List<AuthenticationMethod> getAuthenticationMethods(HttpServletRequest request);

}
