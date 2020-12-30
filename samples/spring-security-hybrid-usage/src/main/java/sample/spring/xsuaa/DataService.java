package sample.spring.xsuaa;

import com.sap.cloud.security.token.Token;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

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
        String zoneId = ((Token)SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getZoneId();
        return "You got the sensitive data for zone '" + zoneId + "'.";
    }
}
