package com.sap.cloud.security.config;

import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.environment.servicebinding.api.TypedMapView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.List;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.ServiceConstants.IAS.DOMAINS;
import static com.sap.cloud.security.config.ServiceConstants.SERVICE_PLAN;

public class ServiceBindingMapper {
    private static final Logger LOGGER = LoggerFactory.getLogger(ServiceBindingMapper.class);

    /**
     * Parses a service binding by extracting the configuration information and passing it to a configuration builder.
     * @return a new {@link OAuth2ServiceConfigurationBuilder} that is configured based on the given {@link ServiceBinding}.
     */
    @Nullable
    public static OAuth2ServiceConfigurationBuilder mapToOAuth2ServiceConfigurationBuilder(ServiceBinding b) {
        if (b.getServiceName().isEmpty()) {
            LOGGER.error("Ignores Service Binding with name {} as service name is not provided.", b.getName());
            return null;
        }

        final Service service = Service.from(b.getServiceName().get());
        if (service == null) {
            LOGGER.error(
                    "Service name {} is unknown. Could not create a OAuth2ServiceConfiguration from a service binding.",
                    b.getServiceName().get());
            return null;
        }

        TypedMapView credentials = TypedMapView.ofCredentials(b);
        OAuth2ServiceConfigurationBuilder builder = OAuth2ServiceConfigurationBuilder.forService(service)
                .withProperties(credentials.getEntries(String.class))
                .withProperty(SERVICE_PLAN, b.getServicePlan().orElse(ServiceConstants.Plan.APPLICATION.name()).toUpperCase());

        if (IAS.equals(service)) {
            parseDomains(builder, credentials);
        }

        return builder;
    }

    /**
     * Parses the 'domains' key in the credentials of an IAS configuration and configures the given builder with them if present.
     *
     * @param credentials value of JSON key 'credentials' in an IAS service configuration
     */
    private static void parseDomains(OAuth2ServiceConfigurationBuilder builder, TypedMapView credentials) {
        List<String> domains;
        if(credentials.getKeys().contains(DOMAINS)) {
            domains = credentials.getListView(DOMAINS).getItems(String.class);
        } else {
            LOGGER.warn("No domains found in IAS credentials.");
            return;
        }

        LOGGER.info("Domain(s) {} found in IAS credentials.", domains);
        builder.withDomains(domains.toArray(new String[]{}));
    }
}