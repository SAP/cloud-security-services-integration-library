package com.sap.cloud.security.xsuaa;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * Interface to access the Xsuaa binding information in the 
 * application environment. Since there can potentially be
 * multiple instances of XSUAA bound, instances of this 
 * interface will return a map of {@link XsuaaBindingInfo} objects. 
 */
public interface XsuaaServiceBindings extends Serializable {
    
    /**
     * Interface to access the XSUAA binding information of a single 
     * bound XSUAA instance.
     */
    interface XsuaaBindingInfo extends Serializable {
        String getLabel();
        String getPlan();
        String getName();
        String getInstanceName();
        List<String> getTags();
        String getBindingName();
        Credentials getCredentials();
        
        /*
        "label":         "xsuaa",
        "provider":      null,
        "plan":          "application",
        "name":          "d056076-netflix-xsuaa",
        "tags":          ["xsuaa"],
        "instance_name": "d056076-netflix-xsuaa",
        "binding_name":  null,
        "credentials" :  {...}
        */
    }
    
    /**
     * Interface to access the credentials information
     * of a single bound XSUAA instance.
     */
    interface Credentials extends Serializable {
        String getUaaDomain();
        String getTenantMode();
        String getServiceBrokerUrl();
        String getClientId();
        String getClientSecret();
        String getXsAppName();
        String getIdentityZone();
        String getIdentityZoneId();
        String getTenantId();
        String getBaseUrl();
        String getVerificationKey();
        
        /*
        "credentials": {
            "uaadomain":       "authentication.eu10.hana.ondemand.com",
            "tenantmode":      "shared",
            "sburl":           "https://internal-xsuaa.authentication.eu10.hana.ondemand.com",
            "clientid":        "sb-spring-netflix-demo!t12291",
            "verificationkey": "-----BEGIN PUBLIC KEY-----MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwThn6OO9kj0bchkOGkqYBnV1dQ3zU/xtj7Kj7nDd8nyRMcEWCtVzrzjzhiisRhlrzlRIEY82wRAZNGKMnw7cvCwNixcfcDJnjzgr2pJ+5/yDZUc0IXXyIWPZD+XdL+0EogC3d4+fqyvg/BF/F0t2hKHWr/UTXE6zrGhBKaL0d8rKfYd6olGWigFd+3+24CKI14zWVxUBtC+P9Fhngc9DRzkXqhxOK/EKn0HzSgotf5duq6Tmk9DCNM4sLW4+ERc6xzrgbeEexakabvax/Az9WZ4qhwgw+fwIhKIC7WLwCEJaRsW4m7NKkv+eJR2LKYesuQ9SVAJ3EXV86RwdnH4uAv7lQHsKURPVAQBlranSqyQu0EXs2N9OlWTxe+FyNkIvyZvoLrZl/CdlYc8AKxRm5rn2/88nkrYQ0XZSrnICM5FRWgVF2hn5KfZGwtBN85/D4Yck6B3ocMfyX7e4URUm9lRPQFUJGTXaZnEIge0R159HUwhTN1HvyXrs6uT1ZZmW+c3p47dw1+LmUf/hIf8zd+uvHQjIeHEJqxjqfyA8yqAFKRHKVFrwnwdMHIsRap2EKBhHMfeVf0P2th5C9MggYoGCvdIaIUgMBX3TtCdvGrcWML7hnyS2zkrlA8SoKJnRcRF2KxWKs355FhpHpzqyZflO5l98+O8wOsFjGpL9d0ECAwEAAQ==-----END PUBLIC KEY-----",
            "xsappname":       "spring-netflix-demo!t12291",
            "identityzone":    "d056076-sub1",
            "identityzoneid":  "d22b9a7f-53b2-4f88-8298-cc51f86e7f68",
            "clientsecret":    "2Tc2Xz7DNy4KiACwvunulmxF32w=",
            "tenantid":        "d22b9a7f-53b2-4f88-8298-cc51f86e7f68",
            "url":             "https://d056076-sub1.authentication.eu10.hana.ondemand.com"
        }
        */
    }
    
    /**
     * Gets the binding information for all bound XSUAA instances.
     * The returned object maps the instance name of each XSUAA instance to its binding information.
     * <p>
     * <b>Note:</b> It is up to the implementation when this map is created. It may be created once and cached, or re-created every time them method is called.<br>
     *              Applications are advised to cache the information returned by this method, as calling it might incur parsing the environment again.
     * </p>
     * @return the bound XSUAA instances' binding information.
     */
    public Map<String, XsuaaBindingInfo> getXsuaaBindingInformation();
}
