package sample.spring.xsuaa;

import com.sap.cloud.security.adapter.spring.SAPOfflineTokenServicesCloud;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

import static org.springframework.http.HttpMethod.GET;

@Configuration
@EnableWebSecurity(debug = true)
@EnableResourceServer
public class SecurityConfiguration extends ResourceServerConfigurerAdapter {

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.NEVER)
				.and()
				.authorizeRequests()
				.antMatchers(GET, "/hello-token").access("#oauth2.hasScopeMatching('Display')")
				.antMatchers(GET, "/hello-servlet").authenticated()
				.anyRequest()
				.authenticated();
	}

	@Bean
	protected SAPOfflineTokenServicesCloud offlineTokenServicesBean() {
		return new SAPOfflineTokenServicesCloud().setLocalScopeAsAuthorities(true);
	}
}
