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
        String getProvider();
        Credentials getCredentials();
        
        /*
        "label":         "xsuaa",
        "provider":      null,
        "plan":          "application",
        "name":          "some-xsuaa",
        "tags":          ["xsuaa"],
        "instance_name": "some-xsuaa",
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
        String getApiUrl();
        
        /*
        "credentials": {
          "tenantmode": "dedicated",
          "sburl": "https://internal-xsuaa.authentication.eu10.hana.ondemand.com",
          "clientid": "YOUR-CLIENT-ID",
          "xsappname": "YOUR-XS-APP-NAME",
          "clientsecret": "YOUR-CLIENT-SECRET",
          "url": "https://YOUR-TENANT.authentication.eu10.hana.ondemand.com",
          "uaadomain": "authentication.eu10.hana.ondemand.com",
          "verificationkey": "-----BEGIN PUBLIC KEY-----...YOUR KEY...-----END PUBLIC KEY-----",
          "apiurl": "https://api.authentication.eu10.hana.ondemand.com",
          "identityzone": "YOUR-TENANT",
          "identityzoneid": "d22b9a7f-53b2-4f88-8298-cc51f86e7f68",
          "tenantid": "d22b9a7f-53b2-4f88-8298-cc51f86e7f68"
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
