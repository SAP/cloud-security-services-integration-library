package sample.spring.xsuaa.datalayer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of the {@link DataLayer} interface.
 * Notice that no authority checks need to be implemented
 * here. This will all be taken care of by Spring global
 * method security.
 * 
 * @see DataLayer 
 */
public class DataLayerImpl implements DataLayer {

    private static final Logger logger = LoggerFactory.getLogger(DataLayerImpl.class);
    
    @Override
    public String readData() {
        logger.info("Reading data.");
        return "You got the data";
    }

    @Override
    public void writeData(String data) {
        logger.info("Writing data: {}", data);
    }
}
