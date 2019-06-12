package sample.spring.xsuaa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

/**
 * Simple DataLayer interface that shows how Spring global message security
 * can be used to control access to data objects on a method level.
 */
@Service
public class DataService {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * Reads data from the data layer.
     * User requires scope {@code Read}
     * for this to succeed.
     */
    @PreAuthorize("hasAuthority('Read')")
    String readData() {
        logger.info("Reading data.");
        return "You got the data";
    }

    /**
     * Writes data to the data layer.
     * User requires scope {@code Write}
     * for this to succeed.
     *
     * @param data the data to be written.
     */
    @PreAuthorize("hasAuthority('Write')")
    void writeData(String data) {
        logger.info("Writing data: {}", data);
    }
}
