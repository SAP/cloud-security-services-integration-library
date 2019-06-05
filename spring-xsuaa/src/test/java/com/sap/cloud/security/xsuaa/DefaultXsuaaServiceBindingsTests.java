package com.sap.cloud.security.xsuaa;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.env.MockEnvironment;

import com.sap.cloud.security.xsuaa.DefaultXsuaaServiceBindings.DefaultCredentials;
import com.sap.cloud.security.xsuaa.DefaultXsuaaServiceBindings.DefaultXsuaaBindingInfo;
import com.sap.cloud.security.xsuaa.XsuaaServiceBindings.Credentials;
import com.sap.cloud.security.xsuaa.XsuaaServiceBindings.XsuaaBindingInfo;

public class DefaultXsuaaServiceBindingsTests {

    File envFile;
    
    @Before
    public void setUp() throws Exception {
        envFile = new File("./test.file");
        envFile.createNewFile();
    }
    
    @After
    public void tearDown() throws Exception {
        envFile.delete();
    }

    @Test
    public final void test_constructor_withEnvironment() {
        MockEnvironment env = new MockEnvironment();
        env.setProperty("VCAP_SERVICES", "{}");
        new DefaultXsuaaServiceBindings(env);
    }
    
    @Test
    public final void test_constructor_withEnvironment_throwsIf_environmentIsNull() {
        assertThatThrownBy(() -> {
            new DefaultXsuaaServiceBindings((Environment)null);
        }).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Environment must not be null");
    }
    
    @Test
    public final void test_constructor_withEnvironment_throwsIf_noVcapServicesPresentInEnvironment() {
        MockEnvironment env = new MockEnvironment();
        assertThatThrownBy(() -> {
            new DefaultXsuaaServiceBindings(env);
        }).isInstanceOf(RuntimeException.class).hasMessageContaining("Could not find VCAP_SERVICES in environment");
    }

    @Test
    public final void test_constructor_withFile() {
        new DefaultXsuaaServiceBindings(envFile);
    }
    
    @Test
    public final void test_constructor_withFile_throwsIf_FileIsNullOrNonExistent() {
        assertThatThrownBy(() -> {
            new DefaultXsuaaServiceBindings((File) null);
        }).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("File must not be null");
        
        String illegalFileName = "Non-Existent.file";
        assertThatThrownBy(() -> {
            new DefaultXsuaaServiceBindings(new File(illegalFileName));
        }).isInstanceOf(IllegalArgumentException.class).hasMessageContaining(String.format("%s does not exist", illegalFileName));
    }

    @Test
    public final void test_getXsuaaBindingInformation() throws IOException {
        
        // using file. 
        
        ClassPathResource testResource = new ClassPathResource("vcap-services.json");
        File vcapServicesFile = testResource.getFile();
        
        DefaultXsuaaServiceBindings bindings = new DefaultXsuaaServiceBindings(vcapServicesFile);
        checkBindingInfoCompleteness(bindings.getXsuaaBindingInformation());
        
        // using environment.
        
        String vcapJson = readVcapJsonFromFile(vcapServicesFile);
        MockEnvironment env = new MockEnvironment();
        env.setProperty("VCAP_SERVICES", vcapJson);
        bindings = new DefaultXsuaaServiceBindings(env);
        
        checkBindingInfoCompleteness(bindings.getXsuaaBindingInformation());
    }
    
    private void checkBindingInfoCompleteness(Map<String, XsuaaBindingInfo> bindingInfoMap) {
        assertNotNull("Bindings map must not be null.", bindingInfoMap);
        assertEquals("Bindings map should contain 2 entries.", 2, bindingInfoMap.size());
        
        XsuaaBindingInfo first = bindingInfoMap.get("xsuaa-authentication-1");
        XsuaaBindingInfo second = bindingInfoMap.get("xsuaa-authentication-2");
        
        assertNotNull("Missing expected XSUAA instance information.", first);
        assertNotNull("Missing expected XSUAA instance information.", second); 
        
        checkXsuaaBindingCompleteness(first, "xsuaa-authentication-1");
        checkXsuaaBindingCompleteness(second, "xsuaa-authentication-2");
    }
    
    private void checkXsuaaBindingCompleteness(XsuaaBindingInfo info, String expectedInstanceName) {
        assertEquals("xsuaa", info.getLabel());
        assertEquals("application", info.getPlan());
        assertEquals(expectedInstanceName, info.getInstanceName());
        assertEquals(expectedInstanceName, info.getName());
        assertNull(info.getBindingName());
        assertNull(info.getProvider());
        assertNotNull(info.getTags());
        assertEquals(1, info.getTags().size());
        
        Credentials credentials = info.getCredentials();
        assertNotNull(credentials);
        assertEquals("dedicated", credentials.getTenantMode());
        assertEquals("https://internal-xsuaa.authentication.eu10.hana.ondemand.com", credentials.getServiceBrokerUrl());
        assertEquals("YOUR-CLIENT-ID", credentials.getClientId());
        assertEquals("YOUR-CLIENT-SECRET", credentials.getClientSecret());
        assertEquals("YOUR-XS-APP-NAME", credentials.getXsAppName());
        assertEquals("https://YOUR-TENANT.authentication.eu10.hana.ondemand.com", credentials.getBaseUrl());
        assertEquals("authentication.eu10.hana.ondemand.com", credentials.getUaaDomain());
        assertEquals("-----BEGIN PUBLIC KEY-----...YOUR KEY...-----END PUBLIC KEY-----", credentials.getVerificationKey());
        assertEquals("https://api.authentication.eu10.hana.ondemand.com", credentials.getApiUrl());
        assertEquals("YOUR-TENANT", credentials.getIdentityZone());
        assertEquals("d22b9a7f-53b2-4f88-8298-cc51f86e7f68", credentials.getIdentityZoneId());
        assertEquals("d22b9a7f-53b2-4f88-8298-cc51f86e7f68", credentials.getTenantId());
    }

    @Test
    public final void test_getXsuaaBindingInformation_throwsIf_VcapServicesIsNull() {
        assertThatThrownBy(() -> {
            DefaultXsuaaServiceBindings bindings = new DefaultXsuaaServiceBindings(envFile);
            bindings.getXsuaaBindingInformation();
        }).isInstanceOf(RuntimeException.class).hasMessageContaining("Unable to parse XSUAA service binding information from environment");
    }
    
    @Test
    public final void test_getXsuaaBindingInformation_throwsIf_VcapServicesDoesNotContainXsuaaInformation() {
        
        assertThatThrownBy(() -> {
            MockEnvironment env = new MockEnvironment();
            env.setProperty("VCAP_SERVICES", "{}");
            DefaultXsuaaServiceBindings bindings = new DefaultXsuaaServiceBindings(env);
            bindings.getXsuaaBindingInformation();
        }).isInstanceOf(RuntimeException.class).hasMessageContaining("Unable to parse XSUAA service binding information from environment");
    }
    
    @Test
    public final void test_serializationIDs() {
        assertNotNull(DefaultXsuaaServiceBindings.getSerialVersionUid());
        assertNotNull(DefaultXsuaaBindingInfo.getSerialVersionUid());
        assertNotNull(DefaultCredentials.getSerialVersionUid());
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

}
