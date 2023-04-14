package com.sap.cloud.security.config;

import com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.environment.servicebinding.api.ServiceBindingAccessor;
import nl.altindag.log.LogCaptor;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests whether ServiceBindingMapper correctly handles 'domains' key in service configurations.
 * Asserts that both 'domains' values given as String array or as single String value are accepted.
 * Asserts that 'domain' value given as single String value is also accepted as fall-back for backward compatibility.
 * Asserts that a warning is printed when no domains are found in an IAS configuration.
 */
class ServiceBindingMapperDomainsTest {
    private static ServiceBinding xsuaaBinding;
    private static ServiceBinding iasBinding, iasBindingSingleDomain, iasBindingDomainsMissing;
    private LogCaptor logCaptor;

    @BeforeAll
    static void setupClass() throws IOException {
        xsuaaBinding = readServiceBindingFromJson(Service.XSUAA, "/vcapXsuaaServiceSingleBinding.json");
        iasBinding = readServiceBindingFromJson(Service.IAS, "/vcapIasServiceSingleBinding.json");
        iasBindingSingleDomain = readServiceBindingFromJson(Service.IAS, "/vcapIasServiceSingleDomain.json");
        iasBindingDomainsMissing = readServiceBindingFromJson(Service.IAS, "/vcapIasServiceDomainsMissing.json");
    }

    private static ServiceBinding readServiceBindingFromJson(Service service, String jsonPath) throws IOException {
        String vcapJson = IOUtils.resourceToString(jsonPath, UTF_8);
        ServiceBindingAccessor sba = new SapVcapServicesServiceBindingAccessor(any -> vcapJson);

        return sba.getServiceBindings().stream()
                .filter(b -> service.equals(Service.from(b.getServiceName().orElse(""))))
                .findFirst().get();
    }

    @BeforeEach
    void setup() {
        logCaptor = LogCaptor.forClass(ServiceBindingMapper.class);
    }

    @Test
    void getXsuaaConfiguration() {
        OAuth2ServiceConfiguration config = ServiceBindingMapper.mapToOAuth2ServiceConfigurationBuilder(xsuaaBinding).build();
        assertThat(config.getDomains()).isEmpty();
    }

    @Test
    void getIasConfiguration() {
        OAuth2ServiceConfiguration config = ServiceBindingMapper.mapToOAuth2ServiceConfigurationBuilder(iasBinding).build();
        assertThat(config.getDomains()).containsExactly("myauth.com", "my.auth.com");
    }

    @Test
    void getIasConfigurationWithSingleDomain() {
        OAuth2ServiceConfiguration config = ServiceBindingMapper.mapToOAuth2ServiceConfigurationBuilder(iasBindingSingleDomain).build();
        assertThat(config.getDomains()).containsExactly("domain1");
    }

    @Test
    void getIasConfigurationWithDomainsMissing() {
        OAuth2ServiceConfiguration config = ServiceBindingMapper.mapToOAuth2ServiceConfigurationBuilder(iasBindingDomainsMissing).build();
        assertThat(config.getDomains()).isEmpty();

        assertThat(logCaptor.getWarnLogs()).contains("Neither 'domains' nor 'domain' found in IAS credentials.");
    }
}