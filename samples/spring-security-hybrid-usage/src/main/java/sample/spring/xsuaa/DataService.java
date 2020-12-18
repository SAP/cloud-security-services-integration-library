package sample.spring.xsuaa;

import com.sap.cloud.security.xsuaa.token.SpringSecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.security.Security;

/**
 * Simple DataLayer interface that shows how Spring global message security
 * can be used to control access to data objects on a method level.
 */
@Service
public class DataService {
    /**
     * Reads sensitive data from the data layer.
     * User requires scope {@code Admin}
     * for this to succeed.
     *
     */
    String readSensitiveData() {
        String zoneId = SpringSecurityContext.getToken().getZoneId();
        return "You got the sensitive data for zone '" + zoneId + "'.";
    }
}
