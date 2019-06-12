package testservice.api.nohttp;

import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;

import com.sap.xs2.security.container.SecurityContext;

@Service
@Profile({ "test.api.nohttp" })
public class MyEventHandler {
	private static final Logger LOGGER = LoggerFactory.getLogger(MyEventHandler.class);

	@Value("${xsuaa.xsappname}")
	String xsappname;

	@Autowired
	JwtDecoder jwtDecoder;

	public void onEvent(String myEncodedJwtToken) {
		if (myEncodedJwtToken != null) {
			Jwt jwtToken = jwtDecoder.decode(myEncodedJwtToken);
			SecurityContext.init(xsappname, jwtToken, true);
		}
		try {
			handleEvent();
		} finally {
			SecurityContext.clear();
		}
	}

	void handleEvent() {
		Collection<GrantedAuthority> authorities = (Collection<GrantedAuthority>) SecurityContext.getToken()
				.getAuthorities();
		if (!authorities.contains(new SimpleGrantedAuthority("Display"))) {
			throw new AccessDeniedException("Missing Authorization.");
		}
		LOGGER.info("Event handled properly");
	}
}
