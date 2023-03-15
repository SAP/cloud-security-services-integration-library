package com.sap.cloud.security.config;

import com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor;
import com.sap.cloud.security.config.cf.ServiceConstants;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

class ServiceBindingEnvironmentTest {

    private static String singleXsuaaConfiguration;
    private static String multipleXsuaaConfigurations;
    private static String singleIasConfiguration;

    @BeforeAll
    static void setUp() throws IOException {
        singleXsuaaConfiguration = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);
        multipleXsuaaConfigurations = IOUtils.resourceToString("/vcapXsuaaServiceMultipleBindings.json", UTF_8);
        singleIasConfiguration = IOUtils.resourceToString("/vcapIasServiceSingleBinding.json", UTF_8);
    }

    @Test
    void getNumberOfXsuaaConfigurations() {
        ServiceBindingEnvironment cut = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> singleIasConfiguration));
        assertEquals(0, cut.getNumberOfXsuaaConfigurations());

        cut = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> singleXsuaaConfiguration));
        assertEquals(1, cut.getNumberOfXsuaaConfigurations());

        cut = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> multipleXsuaaConfigurations));
        assertEquals(2, cut.getNumberOfXsuaaConfigurations());
    }

    @Test
    void getXsuaaConfiguration() {
        ServiceBindingEnvironment cut = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> singleIasConfiguration));
        assertNull(cut.getXsuaaConfiguration());

        cut = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> singleXsuaaConfiguration));
        assertNotEquals(null, cut.getXsuaaConfiguration());
    }

    @Test
    void getXsuaaConfigurationForTokenExchange() {
        ServiceBindingEnvironment cut = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> multipleXsuaaConfigurations));
        assertThat(ServiceConstants.Plan.BROKER.toString(), is(equalToIgnoringCase(cut.getXsuaaConfigurationForTokenExchange().getProperty(ServiceConstants.SERVICE_PLAN))));

        cut = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> singleXsuaaConfiguration));
        assertNotNull(cut.getXsuaaConfigurationForTokenExchange());
    }

    @Test
    void getIasConfiguration() {
        ServiceBindingEnvironment cut = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> singleXsuaaConfiguration));
        assertNull(cut.getIasConfiguration());

        cut = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> singleIasConfiguration));
        assertNotEquals(null, cut.getIasConfiguration());
    }

    @Test
    void getServiceConfigurations() {
        ServiceBindingEnvironment cut = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> singleIasConfiguration));
        Map<Service, Map<ServiceConstants.Plan, OAuth2ServiceConfiguration>> configs = cut.getServiceConfigurations();
        assertThat(configs.get(Service.XSUAA).entrySet(), is((empty())));
        assertThat(configs.get(Service.IAS).entrySet(), hasSize(1));

        cut = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> singleXsuaaConfiguration));
        configs = cut.getServiceConfigurations();
        assertThat(configs.get(Service.XSUAA).entrySet(), hasSize(1));
        assertThat(configs.get(Service.IAS).entrySet(), is(empty()));

        cut = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> multipleXsuaaConfigurations));
        configs = cut.getServiceConfigurations();
        assertThat(configs.get(Service.XSUAA).entrySet(), hasSize(2));
        assertThat(configs.get(Service.IAS).entrySet(), is(empty()));
    }

    @Test
    void supportLegacyMode() {
        ServiceBindingEnvironment cut = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> singleXsuaaConfiguration));
        assertFalse(cut.getXsuaaConfiguration().isLegacyMode());

        String aJSONContainingXs_Api = "{\"xs_api\" : \"\"}";
        cut = new ServiceBindingEnvironment(new SapVcapServicesServiceBindingAccessor(any -> singleXsuaaConfiguration))
                .withEnvironmentVariableReader(vcap_application -> aJSONContainingXs_Api);
        assertTrue(cut.getXsuaaConfiguration().isLegacyMode());
    }
}