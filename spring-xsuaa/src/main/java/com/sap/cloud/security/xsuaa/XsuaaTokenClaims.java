package com.sap.cloud.security.xsuaa;

/**
 * Interface with static constants 
 * denoting custom XSUAA Jwt claims.
 */
public interface XsuaaTokenClaims {
    final String CLAIM_USER_NAME = "user_name";
    final String CLAIM_GIVEN_NAME = "given_name";
    final String CLAIM_FAMILY_NAME = "family_name";
    final String CLAIM_EMAIL = "email";
    final String CLAIM_CLIENT_ID = "cid";
    final String CLAIM_ORIGIN = "origin";
    final String CLAIM_GRANT_TYPE = "grant_type";
    final String CLAIM_ZDN = "zdn";
    final String CLAIM_ZONE_ID = "zid";
    final String CLAIM_SERVICEINSTANCEID = "serviceinstanceid";
    final String CLAIM_ADDITIONAL_AZ_ATTR = "az_attr";
    final String CLAIM_EXTERNAL_CONTEXT = "ext_ctx";
    final String CLAIM_EXTERNAL_ATTR = "ext_attr";
    final String CLAIM_SCOPE = "scope";
}
