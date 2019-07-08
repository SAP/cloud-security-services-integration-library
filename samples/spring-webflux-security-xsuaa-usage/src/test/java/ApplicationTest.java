import com.sap.cloud.security.xsuaa.autoconfiguration.XsuaaAutoConfiguration;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = { XsuaaAutoConfiguration.class })
public class ApplicationTest {

    @Test
    public void contextLoads() {
    }

}