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
import com.sap.cloud.security.json.DefaultJsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.config.ServiceConstants.IAS.DOMAINS;
import static com.sap.cloud.security.config.ServiceConstants.SERVICE_PLAN;
import static com.sap.cloud.security.config.ServiceConstants.VCAP_APPLICATION;

/**
 * Accessor for service configurations that are defined in the environment.
 * Uses a {@link com.sap.cloud.environment.servicebinding.api.ServiceBindingAccessor} to read service bindings from the environment
 * and supplies accessor methods for service-specific configuration objects parsed from these bindings. *
 */
public class ServiceBindingEnvironment implements Environment {
    private static final Logger LOGGER = LoggerFactory.getLogger(ServiceBindingEnvironment.class);
    private final ServiceBindingAccessor serviceBindingAccessor;
    private UnaryOperator<String> environmentVariableReader = System::getenv;
    private Map<Service, Map<ServiceConstants.Plan, OAuth2ServiceConfiguration>> serviceConfigurations;

    /** Uses the {@link com.sap.cloud.environment.servicebinding.api.DefaultServiceBindingAccessor} singleton to read service bindings from the environment.  */
    public ServiceBindingEnvironment() {
        this(DefaultServiceBindingAccessor.getInstance());
    }

    /**
     * Uses the given ServiceBindingAccessor to read service bindings from the environment.
     * For instance, a {@link com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor} can be used
     * to get service configurations for testing based on a local JSON.
     */
    public ServiceBindingEnvironment(ServiceBindingAccessor serviceBindingAccessor) {
        this.serviceBindingAccessor = serviceBindingAccessor;
    }

    /**
     * Overwrites {@link System#getenv} with a custom environment variable reader.
     * The given reader is only used to determine if an XS legacy environment is present.
     * Instead, the reading of service bindings is based on the ServiceBindingAccessor supplied during construction.
     */
    public ServiceBindingEnvironment withEnvironmentVariableReader(UnaryOperator<String> environmentVariableReader) {
        this.environmentVariableReader = environmentVariableReader;
        this.clearServiceConfigurations(); // re-compute service configurations on next access
        return this;
    }

    /**
     * Gets the configuration of the primary XSUAA service binding.
     * The primary binding is determined based on the service plan.
     * The priority of the service plans used for this, is (from high to low priority):
     * <p><ul>
     *     <li>APPLICATION</li>
     *     <li>BROKER</li>
     *     <li>SPACE</li>
     *     <li>DEFAULT</li>
     * </ul></p>
     */
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

    /**
     * Gets the configuration of the XSUAA service binding that is used for token exchange.
     * Returns the configuration of the service binding with service plan BROKER if present,
     * otherwise delegates to {@link ServiceBindingEnvironment#getXsuaaConfiguration()}.
     */
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

    /**
     * Gives access to all service configurations parsed from the environment.
     * The service configurations are parsed on the first access, then cached.
     * @return the service configurations grouped first by service, then by service plan.
     */
    @Override
    public Map<Service, Map<ServiceConstants.Plan, OAuth2ServiceConfiguration>> getServiceConfigurations() {
        if(serviceConfigurations == null) {
            this.readServiceConfigurations();
        }

        return serviceConfigurations;
    }

    /** Parses the service configurations from the environment. */
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

    /**
     * Clears service configurations, so they are computed again on next access.
     * Must be called again if the environment has changed, to update the service configurations that are returned
     * on the next access.
     */
    private void clearServiceConfigurations() {
        this.serviceConfigurations = null;
    }

    /**
     * Parses a service binding by extracting the configuration information and passing it to a configuration builder.
     * @return a new {@link OAuth2ServiceConfigurationBuilder} that is configured based on the given {@link ServiceBinding}.
     */
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
