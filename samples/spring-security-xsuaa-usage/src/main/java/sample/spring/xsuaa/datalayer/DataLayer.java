package sample.spring.xsuaa.datalayer;

import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Simple DataLayer interface that shows how 
 * Spring global message security can be used
 * to control access to data objects on a method
 * level.
 */
public interface DataLayer {

    /**
     * Reads data from the data layer.
     * User requires scope {@code read_resource} 
     * for this to succeed.
     */
    @PreAuthorize("hasAuthority('SCOPE_read_resource')") 
    String readData();
    
    /**
     * Writes data to the data layer.
     * User requires scope {@code write_resource} 
     * for this to succeed. 
     * @param data the data to be written.
     */
    @PreAuthorize("hasAuthority('SCOPE_write_resource')")
    void writeData(String data);
}
