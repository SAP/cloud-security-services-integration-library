package sample.spring.xsuaa;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(classes = Application.class)
@java.lang.SuppressWarnings("squid:S2699")
//test properties are provided with /resources/application.yml
public class ApplicationTest {

	@Test
	public void whenSpringContextIsBootstrapped_thenNoExceptions() {
	}
}