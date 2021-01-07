package sample.spring.xsuaa.junitjupiter;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import sample.spring.xsuaa.Application;

@SpringBootTest(classes = Application.class)
@java.lang.SuppressWarnings("squid:S2699")
//@TestPropertySource are provided with /resources/application.yml
class ApplicationTest {

	@Test
	void whenSpringContextIsBootstrapped_thenNoExceptions() {
	}
}
