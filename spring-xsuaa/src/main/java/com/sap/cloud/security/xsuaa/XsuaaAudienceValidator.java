package com.sap.cloud.security.xsuaa;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import com.sap.cloud.security.xsuaa.XsuaaServiceBindings.XsuaaBindingInfo;

/**
 * An OAuth2TokenValidator to validate Jwt token audiences.
 * This class makes sure that the audiences given in the Jwt token match with the 
 * recipient of the Jwt token. The implementation checks for the 'aud' claim to 
 * find the audiences. In case there are not audiences maintained in the 'aud' claim, 
 * the scopes' application-specific prefixes will be used to derive an audience set. 
 */
public class XsuaaAudienceValidator implements OAuth2TokenValidator<Jwt> {

    private final Logger logger = LoggerFactory.getLogger(XsuaaAudienceValidator.class);
    private final String DOT = ".";
    private Map<String, XsuaaBindingInfo> bindingInfo;

    /**
     * Creates a new validator instance that looks up the XsAppName (and OAuth client ID)
     * from the XsuaaServiceBindings that was extracted from the {@code VCAP_SERVICES} environment.
     * This information is matched against the audiences in the received Jwt token. 
     * 
     * @param xsuaaServiceBindings - the XSUAA service binding information from the {@code VCAP_SERVICES} environment.
     */
    public XsuaaAudienceValidator(XsuaaServiceBindings xsuaaServiceBindings) {
        Assert.notNull(xsuaaServiceBindings, "Xsuaa service bindings must not be null.");
        this.bindingInfo = xsuaaServiceBindings.getXsuaaBindingInformation(); 
    }    

    /* (non-Javadoc)
     * @see org.springframework.security.oauth2.core.OAuth2TokenValidator#validate(org.springframework.security.oauth2.core.AbstractOAuth2Token)
     */
    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        
        String clientIdFromToken = token.getClaimAsString(XsuaaTokenClaims.CLAIM_CLIENT_ID);
        if (clientIdFromToken == null) {
            logger.error("Cannot validate client ID from Jwt! Jwt does not contain 'cid' (client_id) claim.");
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "Cannot validate client ID from JWT! Jwt does not contain 'cid' (client_id) claim.", null);
            return OAuth2TokenValidatorResult.failure(error);
        }
        
        Collection<XsuaaBindingInfo> xsuaaBindingInfos = bindingInfo.values();
        Set<String> processedApplicationIDs = new HashSet<>();
        
        for (XsuaaBindingInfo xsuaaBindingInfo : xsuaaBindingInfos) {
            
            String appId    = xsuaaBindingInfo.getCredentials().getXsAppName();
            String clientId = xsuaaBindingInfo.getCredentials().getClientId();
            
            OAuth2TokenValidatorResult success = performAccessCheck(appId, clientId, token);
            boolean accessGranted = !success.hasErrors(); 
            if (accessGranted) {
                return success;
            }
            
            processedApplicationIDs.add(appId);
        }
        
        String applicationIds = processedApplicationIDs.toString();
        logger.error("Jwt token audience matches none of the following application IDs: {}", applicationIds);
        
        OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, String.format("Jwt token audience matches none of the following application IDs: %s", applicationIds), null);
        return OAuth2TokenValidatorResult.failure(error);
    }

    /**
     * Performs an access check verifying that the XsAppName is part of the audiences 
     * contained in the Jwt token.
     * 
     * @param appId - the XsAppName.
     * @param clientId - the OAuth 2.0 client ID as found in the XSUAA service bindings in the environment.
     * @param token - the received Jwt token.
     * @return the result of the access check.
     */
    private OAuth2TokenValidatorResult performAccessCheck(String appId, String clientId, Jwt token) {
        
        List<String> allowedAudiences = getAllowedAudiences(token);
        String clientIdFromToken = token.getClaimAsString(XsuaaTokenClaims.CLAIM_CLIENT_ID);
        
        // case 1 : token issued by own client (or master)
        if (clientId.equals(clientIdFromToken) || (appId.contains("!b") && clientIdFromToken.contains("|") && clientIdFromToken.endsWith("|" + appId))) {
            logger.debug("Received token issued by own client (self-calling request). Reporting token validation success.");
            return OAuth2TokenValidatorResult.success();
        } 
        else {
            // case 2: foreign token
            if (allowedAudiences.contains(appId)) {
                logger.debug("Jwt token audience matches application ID: {} ! Reporting token validation success.", appId);
                return OAuth2TokenValidatorResult.success();
            } else {
                logger.debug("Jwt token audience does not match application ID: {} ! Reporting token validation failure.", appId);
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, String.format("Jwt token audience does not match application ID: %s !", appId), null);
                return OAuth2TokenValidatorResult.failure(error);
            }
        }
    }

    /**
     * Retrieves the audiences from the token's 'aud' claim. <br>
     * In case the audience list is empty it will fall back to deriving 
     * audiences from the prefixes of the scope names.
     *
     * @param token - the JWT token to inspect for audiences.
     * @return the (possibly empty) list of audiences. 
     */
    protected List<String> getAllowedAudiences(Jwt token) {
        
        List<String> tokenAudiences = token.getAudience();
        
        if (tokenAudiences == null) {
            return getAudiencesFromScopeNames(token);
        }
        
        List<String> returnAudiences = stripSuffixes(tokenAudiences);
        
        return returnAudiences.isEmpty() ? getAudiencesFromScopeNames(token) : returnAudiences;
    }
    
    /**
     * Inspects scopes for values that contain a '.', assuming that everything
     * before the '.' is the XSAppName and that this is specifying the audience.
     * Unfortunately, this is completely wrong for a case where there is a scope
     * of 'uaa.user'. So this method is rather questionable.
     * @param token - the JWT token to get the scopes from. 
     * @return the List of audiences derived from the scopes. 
     */
    private List<String> getAudiencesFromScopeNames(Jwt token) {
        List<String> scopes = getScopes(token);
        List<String> returnValues = new ArrayList<>();
        
        for (String scope : scopes) {
            
            if (scope.isEmpty()) { // don't add empty strings.
                continue;
            }
            
            if (scope.contains(DOT)) {
                String aud = scope.substring(0, scope.indexOf(DOT));
                if (!aud.isEmpty()) { // don't add empty strings.
                    returnValues.add(aud);
                }
            }
        }
        
        return returnValues;
    }
    
    /**
     * Strips any suffixes from audiences.
     * @param tokenAudiences - the audiences from the token.
     * @return the list of stripped audiences.
     */
    private List<String> stripSuffixes(List<String> tokenAudiences) {
        List<String> returnValues = new ArrayList<>();
        
        for (String audience : tokenAudiences) {
            
            if(audience.isEmpty()) { // don't add empty strings.
                continue;
            }
            
            if (audience.contains(DOT)) {
                String strippedAudience = audience.substring(0, audience.indexOf(DOT));
                if(!strippedAudience.isEmpty()) { // don't add empty strings.
                    returnValues.add(strippedAudience);
                }
            } 
            else {
                returnValues.add(audience);
            }
        }
        return returnValues;
    }

    /**
     * Returns the scopes set for the token.
     * @param token - the JWT token to inspect for scopes.
     * @return the list of scopes.
     */
    protected List<String> getScopes(Jwt token) {
        List<String> scopes = null;
        scopes = token.getClaimAsStringList(XsuaaTokenClaims.CLAIM_SCOPE);
        return scopes != null ? scopes : new ArrayList<>();
    }
}