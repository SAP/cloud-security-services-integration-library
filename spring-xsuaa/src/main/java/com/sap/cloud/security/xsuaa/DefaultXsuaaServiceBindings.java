package com.sap.cloud.security.xsuaa;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.core.env.Environment;
import org.springframework.util.Assert;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/**
 * Default implementation of the {@link XsuaaServiceBindings}
 * interface. You can declare instances of this class as a bean 
 * to make it available in your application like this:
 * 
 * <pre class="code">
 * &#064;Bean 
 * XsuaaServiceBindings xsuaaServiceBindings(Environment environment) {
 *     return new DefaultXsuaaServiceBindings(environment);
 * }
 * </pre>
 * 
 * This implementation uses Jackson 2.0 to parse XSUAA binding information 
 * from JSON found in VCAP_SERVICES.
 */
public class DefaultXsuaaServiceBindings implements XsuaaServiceBindings {

    private static final String XSUAA_SERVICE_ID = "xsuaa";

    private static final String VCAP_SERVICES = "VCAP_SERVICES";

    private static final long serialVersionUID = 1825633195138918599L;
    
    private Environment environment;
    private File vcapServicesFile;
    
    
    public DefaultXsuaaServiceBindings(Environment environment) {
        Assert.notNull(environment, "Environment must not be null.");
        
        String vcapServices = environment.getProperty(VCAP_SERVICES);
        if(vcapServices == null) {
            throw new RuntimeException("Could not find VCAP_SERVICES in environment. Make sure your environment has the VCAP_SERVICES variable set and filled JSON contain XSUAA binding information.");
        }
        
        this.environment = environment;
    }
    
    public DefaultXsuaaServiceBindings(File vcapServicesFile) {
        Assert.notNull(vcapServicesFile, "File must not be null.");
        Assert.isTrue(vcapServicesFile.exists(), String.format("File %s does not exist", vcapServicesFile.getAbsolutePath()));
        
        this. vcapServicesFile = vcapServicesFile;
    }

    private String readVcapJsonFromFile(File vcapServicesFile) {
        
        try ( BufferedReader reader = new BufferedReader(new FileReader(vcapServicesFile)) ) {
            StringBuffer buffer = new StringBuffer();
            String line;
            while((line = reader.readLine()) != null) {
                buffer.append(line);
            }
            return buffer.toString();
        }
        catch (FileNotFoundException ex) {
            throw new RuntimeException("Could not find VCAP_SERVICES json file.", ex);
        }
        catch (IOException ex) {
            throw new RuntimeException("Caught exception reading VCAP_SERVICES json file.", ex);
        }
    }
    
    @Override
    public Map<String, XsuaaBindingInfo> getXsuaaBindingInformation() {
        
        String vcapServicesJson = null;
        if(environment != null) {
            vcapServicesJson = environment.getProperty(VCAP_SERVICES);
        }
        else if (vcapServicesFile != null) {
            vcapServicesJson = readVcapJsonFromFile(vcapServicesFile);
        }
                
        if(vcapServicesJson == null) {
            throw new RuntimeException("Unable to parse XSUAA service binding information from environment. Check your environment for VCAP_SERVICES variable.");
        }
        
        try {
            
            ObjectMapper mapper = new ObjectMapper();
            mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
            JsonNode tree = mapper.readTree(vcapServicesJson);
            JsonNode xsuaaNodes = tree.get(XSUAA_SERVICE_ID);
            
            Map<String, XsuaaBindingInfo> bindings = new HashMap<>();
            
            for (JsonNode xsuaaNode : xsuaaNodes) {
                DefaultXsuaaBindingInfo info = mapper.treeToValue(xsuaaNode, DefaultXsuaaBindingInfo.class);
                bindings.put(info.getName(), info);
            }
            
            return bindings;
            
        } catch (IOException e) {
            throw new RuntimeException("Unable to parse XSUAA service binding information from environment.", e);
        }
    }

    @JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
    public static class DefaultXsuaaBindingInfo implements XsuaaBindingInfo {
        private static final long serialVersionUID = 6576943788309003117L;

        private String label;
        private String plan;
        private String name;
        private String instanceName;
        private List<String> tags = new ArrayList<>();
        private String bindingName;
        private Credentials credentials;
        
        public static long getSerialVersionUid() {
            return serialVersionUID;
        }
        
        @Override
        public String getLabel() {
            return label;
        }

        @Override
        public String getPlan() {
            return plan;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public String getInstanceName() {
            return instanceName;
        }

        @Override
        public List<String> getTags() {
            return tags;
        }

        @Override
        public String getBindingName() {
            return bindingName;
        }

        @Override
        public Credentials getCredentials() {
            return credentials;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public void setPlan(String plan) {
            this.plan = plan;
        }

        public void setName(String name) {
            this.name = name;
        }

        public void setInstanceName(String instanceName) {
            this.instanceName = instanceName;
        }

        public void setTags(List<String> tags) {
            this.tags = tags;
        }

        public void setBindingName(String bindingName) {
            this.bindingName = bindingName;
        }

        @JsonDeserialize( as = DefaultCredentials.class)
        public void setCredentials(Credentials credentials) {
            this.credentials = credentials;
        }
    }
    
    @JsonNaming(PropertyNamingStrategy.LowerCaseStrategy.class)
    public static class DefaultCredentials implements Credentials {

        private static final long serialVersionUID = 3655191426181516040L;
        
        private String uaaDomain;
        private String tenantMode;
        private String serviceBrokerUrl;
        private String clientId;
        private String clientSecret;
        private String xsAppName;
        private String identityZone;
        private String identityZoneId;
        private String tenantId;
        private String baseUrl;
        private String verificationKey;
        
        public static long getSerialVersionUid() {
            return serialVersionUID;
        }
        
        @Override
        public String getUaaDomain() {
            return uaaDomain;
        }

        @Override
        public String getTenantMode() {
            return tenantMode;
        }

        @Override
        @JsonProperty("sburl")
        public String getServiceBrokerUrl() {
            return serviceBrokerUrl;
        }

        @Override
        public String getClientId() {
            return clientId;
        }

        @Override
        public String getClientSecret() {
            return clientSecret;
        }

        @Override
        public String getXsAppName() {
            return xsAppName;
        }

        @Override
        public String getIdentityZone() {
            return identityZone;
        }

        @Override
        public String getIdentityZoneId() {
            return identityZoneId;
        }

        @Override
        public String getTenantId() {
            return tenantId;
        }

        @Override
        @JsonProperty("url")
        public String getBaseUrl() {
            return baseUrl;
        }

        @Override
        public String getVerificationKey() {
            return verificationKey;
        }

        public void setXsAppName(String xsAppName) {
            this.xsAppName = xsAppName;
        }

        @JsonProperty("url")
        public void setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
        }

        public void setUaaDomain(String uaaDomain) {
            this.uaaDomain = uaaDomain;
        }

        public void setTenantMode(String tenantMode) {
            this.tenantMode = tenantMode;
        }

        @JsonProperty("sburl")
        public void setServiceBrokerUrl(String serviceBrokerUrl) {
            this.serviceBrokerUrl = serviceBrokerUrl;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public void setIdentityZone(String identityZone) {
            this.identityZone = identityZone;
        }

        public void setIdentityZoneId(String identityZoneId) {
            this.identityZoneId = identityZoneId;
        }

        public void setTenantId(String tenantId) {
            this.tenantId = tenantId;
        }

        public void setVerificationKey(String verificationKey) {
            this.verificationKey = verificationKey;
        }
    }
}
