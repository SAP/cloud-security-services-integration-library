/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import com.sap.cloud.environment.servicebinding.api.DefaultServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.environment.servicebinding.api.ServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.TypedMapView;
import com.sap.cloud.security.config.cf.ServiceConstants;
import com.sap.cloud.security.json.DefaultJsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.*;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.config.cf.ServiceConstants.IAS.DOMAINS;
import static com.sap.cloud.security.config.cf.ServiceConstants.SERVICE_PLAN;
import static com.sap.cloud.security.config.cf.ServiceConstants.VCAP_APPLICATION;

public class ServiceBindingEnvironment implements Environment {
    private static final Logger LOGGER = LoggerFactory.getLogger(ServiceBindingEnvironment.class);
    private final ServiceBindingAccessor serviceBindingAccessor;
    private UnaryOperator<String> environmentVariableReader = System::getenv;
    private Map<Service, Map<ServiceConstants.Plan, OAuth2ServiceConfiguration>> serviceConfigurations;

    public ServiceBindingEnvironment() {
        this(DefaultServiceBindingAccessor.getInstance());
    }

    public ServiceBindingEnvironment(ServiceBindingAccessor serviceBindingAccessor) {
        this.serviceBindingAccessor = serviceBindingAccessor;
    }

    public void setEnvironmentVariableReader(UnaryOperator<String> environmentVariableReader) {
        this.environmentVariableReader = environmentVariableReader;
        this.clearServiceConfigurations(); // re-compute service configurations on next access
    }

    public ServiceBindingEnvironment withEnvironmentVariableReader(UnaryOperator<String> environmentVariableReader) {
        this.setEnvironmentVariableReader(environmentVariableReader);
        return this;
    }

    @Nullable
    @Override
    public OAuth2ServiceConfiguration getXsuaaConfiguration() {
        return Stream.of(ServiceConstants.Plan.APPLICATION, ServiceConstants.Plan.BROKER, ServiceConstants.Plan.SPACE, ServiceConstants.Plan.DEFAULT)
                .map(plan -> getServiceConfigurations().get(XSUAA).get(plan))
                .filter(Objects::nonNull)
                .findFirst().orElse(null);
    }

    @Override
    public int getNumberOfXsuaaConfigurations() {
        return getServiceConfigurations().get(XSUAA).size();
    }

    @Nullable
    @Override
    public OAuth2ServiceConfiguration getXsuaaConfigurationForTokenExchange() {
        if(getNumberOfXsuaaConfigurations() > 1) {
            return getServiceConfigurations().get(XSUAA).get(ServiceConstants.Plan.BROKER);
        }

        return getXsuaaConfiguration();
    }

    @Nullable
    @Override
    public OAuth2ServiceConfiguration getIasConfiguration() {
        return getServiceConfigurations().get(IAS).values().stream().findFirst().orElse(null);
    }

    @Override
    public Map<Service, Map<ServiceConstants.Plan, OAuth2ServiceConfiguration>> getServiceConfigurations() {
        if(serviceConfigurations == null) {
            this.readServiceConfigurations();
        }

        return serviceConfigurations;
    }

    private void readServiceConfigurations() {
        List<ServiceBinding> serviceBindings = serviceBindingAccessor.getServiceBindings();

        serviceConfigurations =
                Stream.of(Service.values())
                .collect(Collectors.toMap(Function.identity(), service ->
                        serviceBindings.stream()
                        .filter(b -> service.equals(Service.from(b.getServiceName().orElse(""))))
                        .map(ServiceBindingEnvironment::mapServiceBindingToConfigurationBuilder)
                        .filter(Objects::nonNull)
                        .map(builder -> builder.runInLegacyMode(runInLegacyMode()))
                        .map(OAuth2ServiceConfigurationBuilder::build)
                        .collect(Collectors.toMap(config -> ServiceConstants.Plan.from(config.getProperty(SERVICE_PLAN)), Function.identity()))));
    }

    /** Clears service configurations, so they are computed again on next access. */
    private void clearServiceConfigurations() {
        this.serviceConfigurations = null;
    }

    @Nullable
    private static OAuth2ServiceConfigurationBuilder mapServiceBindingToConfigurationBuilder(ServiceBinding b) {
        if (b.getServiceName().isEmpty()) {
            LOGGER.error("Ignores Service Binding with name {} as service name is not provided.", b.getName());
            return null;
        }

        final Service service = Service.from(b.getServiceName().get());
        if (service == null) {
            LOGGER.error(
                    "Service name {} is unknown. Could not create a OAuth2ServiceConfiguration from service binding.",
                    b.getServiceName().get());
            return null;
        }

        OAuth2ServiceConfigurationBuilder builder = OAuth2ServiceConfigurationBuilder.forService(service)
                .withProperties(TypedMapView.ofCredentials(b).getEntries(String.class))
                .withProperty(SERVICE_PLAN,
                        b.getServicePlan().orElse(ServiceConstants.Plan.APPLICATION.name()).toUpperCase());

        if (IAS.equals(service)) {
            List<String> domains = TypedMapView.ofCredentials(b).getListView(DOMAINS).getItems(String.class);
            LOGGER.info("first domain : {}", domains.get(0));
            builder.withDomains(domains.toArray(new String[] {}));
        }

        return builder;
    }

    private boolean runInLegacyMode() {
        String vcapApplicationJson = environmentVariableReader.apply(VCAP_APPLICATION);

        if (vcapApplicationJson != null) {
            return new DefaultJsonObject(vcapApplicationJson).contains("xs_api");
        }

        return false;
    }
}
