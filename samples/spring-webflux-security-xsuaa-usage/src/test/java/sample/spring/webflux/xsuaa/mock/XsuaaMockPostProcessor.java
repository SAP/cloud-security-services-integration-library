package sample.spring.webflux.xsuaa.mock;

import com.sap.cloud.security.xsuaa.mock.XsuaaMockWebServer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Profiles;

public class XsuaaMockPostProcessor implements EnvironmentPostProcessor {

	private static final XsuaaMockWebServer mockAuthorizationServer = new XsuaaMockWebServer();

	@Override
	public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
		if (environment.acceptsProfiles(Profiles.of("uaamock"))) {
			environment.getPropertySources().addFirst(this.mockAuthorizationServer);
		}
	}
}