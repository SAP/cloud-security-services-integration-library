package com.sap.cloud.security.config;

import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.environment.servicebinding.api.TypedMapView;
import com.sap.cloud.security.config.k8s.K8sConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.List;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.cf.CFConstants.IAS.DOMAINS;
import static com.sap.cloud.security.config.cf.CFConstants.SERVICE_PLAN;

@Deprecated
public class ServiceBindingMapper {
	private static final Logger LOGGER = LoggerFactory.getLogger(ServiceBindingMapper.class);

	@Deprecated
	@Nullable
	public static OAuth2ServiceConfigurationBuilder mapToOAuth2ServiceConfigurationBuilder(ServiceBinding b) {
		if (!b.getServiceName().isPresent()) {
			LOGGER.error("Ignores Service Binding with name {} as service name is not provided.", b.getName());
			return null; // as of now, method is never called when service name isn't given
		}

		final Service service = Service.from(b.getServiceName().get());
		if (service == null) {
			LOGGER.error(
					"Service name {} is unknown. Could not create a OAuth2ServiceConfiguration from a service binding.",
					b.getServiceName().get());
			return null;
		}

		OAuth2ServiceConfigurationBuilder builder = OAuth2ServiceConfigurationBuilder.forService(service)
				.withProperties(TypedMapView.ofCredentials(b).getEntries(String.class))
				.withProperty(SERVICE_PLAN,
						b.getServicePlan().orElse(K8sConstants.Plan.APPLICATION.name()).toUpperCase());

		if (IAS.equals(service)) {
			List<String> domains = TypedMapView.ofCredentials(b).getListView(DOMAINS).getItems(String.class);
			LOGGER.info("first domain : {}", domains.get(0));
			builder.withDomains(domains.toArray(new String[] {}));
		}

		return builder;
	}
}