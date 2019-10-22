package sample.spring.xsuaa;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = Application.class)

public class ApplicationTest {

	@Test
	public void whenSpringContextIsBootstrapped_thenNoExceptions() {
	}
}

/*@Configuration
@PropertySource(factory = XsuaaServicePropertySourceFactory.class, value = { "classpath:vcap.json" })
class TestConfiguration {

}*/