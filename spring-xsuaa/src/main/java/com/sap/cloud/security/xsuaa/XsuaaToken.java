package com.sap.cloud.security.xsuaa;

import static com.sap.cloud.security.xsuaa.XsuaaTokenClaims.CLAIM_ADDITIONAL_AZ_ATTR;
import static com.sap.cloud.security.xsuaa.XsuaaTokenClaims.CLAIM_CLIENT_ID;
import static com.sap.cloud.security.xsuaa.XsuaaTokenClaims.CLAIM_EMAIL;
import static com.sap.cloud.security.xsuaa.XsuaaTokenClaims.CLAIM_EXTERNAL_ATTR;
import static com.sap.cloud.security.xsuaa.XsuaaTokenClaims.CLAIM_EXTERNAL_CONTEXT;
import static com.sap.cloud.security.xsuaa.XsuaaTokenClaims.CLAIM_FAMILY_NAME;
import static com.sap.cloud.security.xsuaa.XsuaaTokenClaims.CLAIM_GIVEN_NAME;
import static com.sap.cloud.security.xsuaa.XsuaaTokenClaims.CLAIM_GRANT_TYPE;
import static com.sap.cloud.security.xsuaa.XsuaaTokenClaims.CLAIM_ORIGIN;
import static com.sap.cloud.security.xsuaa.XsuaaTokenClaims.CLAIM_SERVICEINSTANCEID;
import static com.sap.cloud.security.xsuaa.XsuaaTokenClaims.CLAIM_USER_NAME;
import static com.sap.cloud.security.xsuaa.XsuaaTokenClaims.CLAIM_ZDN;
import static com.sap.cloud.security.xsuaa.XsuaaTokenClaims.CLAIM_ZONE_ID;

import java.io.StringWriter;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.Jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.minidev.json.JSONArray;

/**
 * Custom XSUAA token implementation.
 * <p>
 * This class inherits Spring Security's standard Jwt implementation
 * and can be used interchangeably with it. <br>
 * Applications can choose to exchange the standard Jwt implementation
 * with this class in {@link WebSecurityConfigurerAdapter} subclasses
 * or use this class simply as a wrapper for a standard Jwt to have more
 * convenient access to XSUAA-specific token claims. 
 * </p>
 * 
 * <pre class="code">
 * private void configure_ExchangingStandardJwtForXSUAAToken(HttpSecurity http) throws Exception {
 *     
 *     http
 *         .sessionManagement()
 *             .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
 *         .and()
 *             .authorizeRequests()
 *                 .antMatchers("/actuator/**").permitAll()
 *                 .antMatchers("/v1/address").hasAuthority("SCOPE_read_resource") // made possible by the jwtToXsuaaTokenConverterReplacingXSAppName() that was added using .jwtAuthenticationConverter().
 *                 .anyRequest().authenticated()
 *         .and()
 *             .oauth2ResourceServer()
 *                 .jwt()
 *                     .jwtAuthenticationConverter(new XsuaaTokenConverter()); 
 * }
 * </pre>
 */
public class XsuaaToken extends Jwt {
    
    private static final long serialVersionUID = 7192693982373191970L;
    private static final Logger logger = LoggerFactory.getLogger(XsuaaToken.class);
    
    private static final String NEWLINE = "\n";
    
    private static final String CLAIM_XS_USER_ATTRIBUTES   = "xs.user.attributes";
    private static final String GRANTTYPE_CLIENTCREDENTIAL = "client_credentials";
    private static final String UNIQUE_USER_NAME_FORMAT = "user/%s/%s"; // user/<origin>/<logonName>
    private static final String UNIQUE_CLIENT_NAME_FORMAT = "client/%s"; // client/<clientid>

    public XsuaaToken(Jwt jwt) {
        super(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getHeaders(), jwt.getClaims());
    }
    
    /**
     * Returns the subaccount identifier, which can be used as tenant GUID.
     * @return the subaccount identifier.
     */
    public String getSubaccountId() {
        return getClaimAsString(CLAIM_ZONE_ID);
    }

    /**
     * Returns the subdomain of the calling
     * tenant's subaccount.
     *
     * @return the subdomain of the tenant the JWT belongs to.
     */
    public String getSubdomain() {
        return getStringAttributeFromClaim(CLAIM_ZDN, CLAIM_EXTERNAL_ATTR);
    }

    /**
     * Returns the OAuth client identifier of 
     * the authentication token if present.
     * @return the OAuth client ID.
     */
    @Nullable
    public String getClientId() {
        return getClaimAsString(CLAIM_CLIENT_ID);
    }

    /**
     * Returns the OAuth2.0 grant type 
     * used for retrieving / creating this token.
     *
     * @return the grant type
     */
    public String getGrantType() {
        return getClaimAsString(CLAIM_GRANT_TYPE);
    }

    /**
     * Returns the user login name used for authentication, e.g. an email address or other identifier.
     * Note, that a user might exist in multiple identity providers. Thus the following information
     * is required to uniquely identify a user: <br> 
     * 
     * <ul> 
     *  <li> <b>user login name:</b> name of the user in an identity provider, provided by this method.
     *  <li> <b>origin:</b> alias to an identity provider, see {@link #getOrigin()}.
     *  <li> <b>subaccount id:</b> identifier for the subaccount, see {@link #getSubaccountId()}.
     * </ul>
     * 
     * @see #getUniqueUserName()
     *
     * @return the user logon name if present.
     */
    @Nullable
    public String getUserLoginName() {
        return getClaimAsString(CLAIM_USER_NAME);
    }

    /**
     * Returns the user origin. The origin is an alias that refers to a user store in
     * which the user is persisted. For example, users that are authenticated by the
     * UAA itself with a username / password combination have their origin set to the
     * value "uaa". May be null in case this JWT was not created with 
     * OAuth 2.0 client credentials flow.
     *
     * @return the user origin if present.
     */
    @Nullable
    public String getOrigin() {
        return getClaimAsString(CLAIM_ORIGIN);
    }
    
    /**
     * Returns a unique user name of a user, using information from the JWT.
     * For tokens that were issued as a result of a client credentials flow, the 
     * OAuth client ID will be returned in a special format.
     * The following information is required to uniquely identify a user: <br> 
     * 
     * <ul> 
     *  <li> <b>user logon name:</b> name of the user in an identity provider, see {@code #getUserLogonName()}.
     *  <li> <b>origin:</b> alias to an identity provider, see {@code #getOrigin()}.
     *  <li> <b>subaccount id:</b> identifier for the subaccount, see {@code #getSubaccountId()}
     * </ul>
     *
     * If one of this information is not available or wrongly formed, null will be returned.
     *
     * @return unique principal name
     */
    @Nullable
    public String getUniqueUserName() {
        
        if (GRANTTYPE_CLIENTCREDENTIAL.equalsIgnoreCase(getGrantType())) {
            return String.format(UNIQUE_CLIENT_NAME_FORMAT, getClientId());
        }
        
        String origin = getOrigin();
        String userLoginName = getUserLoginName();
        
        if (origin == null) {
            logger.warn("Origin claim not set in JWT. Cannot create unique user name. Returning null.");
            return null;
        }
                       
        if (userLoginName == null) {
            logger.warn("User login name claim not set in JWT. Cannot create unique user name. Returning null.");
            return null;
        }
      
        if (origin.contains("/")) {
            logger.warn("Illegal '/' character detected in origin claim of JWT. Cannot create unique user name. Returing null.");
            return null;
        }
        
        return String.format(UNIQUE_USER_NAME_FORMAT, origin, userLoginName);
    }
    

    /**
     * Returns the given name of the user if present.
     * Will try to find it first in the {@code ext_attr.given_name} claim
     * before trying to find a {@code given_name} claim.
     * @return the given name.
     */
    @Nullable
    public String getGivenName() {
        String externalAttribute = getStringAttributeFromClaim(CLAIM_GIVEN_NAME, CLAIM_EXTERNAL_ATTR);
        return externalAttribute != null ? externalAttribute : getClaimAsString(CLAIM_GIVEN_NAME);
    }

    /**
     * Returns the family name of the user if present.
     * Will try to find it first in the {@code ext_attr.family_name} claim
     * before trying to find a {@code family_name} claim.
     * @return the family name.
     */
    @Nullable
    public String getFamilyName() {
        String externalAttribute = getStringAttributeFromClaim(CLAIM_FAMILY_NAME, CLAIM_EXTERNAL_ATTR);
        return externalAttribute != null ? externalAttribute : getClaimAsString(CLAIM_FAMILY_NAME);
    }
    
    private String getStringAttributeFromClaim(String attributeName, String claimName) {
        Map<String, Object> externalAttribute = getClaimAsMap(claimName);
        return externalAttribute == null ? null : (String) externalAttribute.get(attributeName);
    }

    /**
     * Returns the email address of the user, if present.
     * @return The email address.
     */
    @Nullable
    public String getEmail() {
        return getClaimAsString(CLAIM_EMAIL);
    }

    /**
     * Returns the value of an attribute
     * from the 'xs.user.attributes' claim.
     * Will first try to find the attribute in 
     * 'ext_ctx' claim. Will return null if nothing
     * found.
     *
     * @param attributeName name of the attribute inside 
     *                      'ext_ctx' or 'xs.user.attributes'.
     * @return the attribute values array
     */
    @Nullable
    public String[] getXSUserAttribute(String attributeName) {
        String[] attributeValue = getStringListAttributeFromClaim(attributeName, CLAIM_EXTERNAL_CONTEXT);
        return attributeValue != null ? attributeValue : getStringListAttributeFromClaim(attributeName, CLAIM_XS_USER_ATTRIBUTES);  
    }

    /**
     * Additional custom authentication attributes included by the OAuth client
     * component. Note: this is data controlled by the requester of a token. Might
     * be not trustworthy.
     *
     * @param attributeName
     *            name of the authentication attribute
     * @return additional attribute value
     */
    @Nullable
    public String getAdditionalAuthAttribute(String attributeName) {
        return getStringAttributeFromClaim(attributeName, CLAIM_ADDITIONAL_AZ_ATTR);
    }

    /**
     * Returns the XSUAA clone instance ID, if present.
     * This will only be set for tokens that were issued by an 
     * XSUAA with plan broker. Contains the service instance id if present.
     *
     * @return the XSUAA clone service instance id.
     */
    @Nullable
    public String getCloneServiceInstanceId() {
        return getStringAttributeFromClaim(CLAIM_SERVICEINSTANCEID, CLAIM_EXTERNAL_ATTR);
    }

    private String[] getStringListAttributeFromClaim(String attributeName, String claimName) {
        
        // TODO: this is horrible JSON coding! Fix it.
        
        Map<String, Object> claimObject = getClaimAsMap(claimName);
        if (claimObject == null) {
            logger.debug("Claim %s not found. Returning null.", claimName);
            return null;
        }
        
        JSONArray jsonArray = (JSONArray) claimObject.get(attributeName);
        if(jsonArray == null) {
            logger.debug("Attribute %s in claim %s not found. Returning null.", attributeName, claimName);
            return null;
        }
        
        String[] attributeValues = new String[jsonArray.size()];
        
        for (int i = 0; i < jsonArray.size(); i++) {
            attributeValues[i] = (String) jsonArray.get(i);
        }
        
        return attributeValues;
    }

    public String toString() {
        Map<String, Object> headers = getHeaders();
        Map<String, Object> claims = getClaims();
        String encodedTokenValue = getTokenValue();
        
        String headersString = print("Headers:", headers);
        String claimsString  = print("Claims:", claims);
        
        return new StringWriter().append(headersString).append(NEWLINE).append(claimsString).append(NEWLINE).append("Encoded Value: ").append(encodedTokenValue).toString();
    }
    
    private String print(String heading, Map<String, Object> map) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(map);
            return new StringWriter().append(heading).append(NEWLINE).append(json).toString();            
        } catch (JsonProcessingException ex) {
            throw new RuntimeException("Error formatting JSON.", ex);
        }
    }
}