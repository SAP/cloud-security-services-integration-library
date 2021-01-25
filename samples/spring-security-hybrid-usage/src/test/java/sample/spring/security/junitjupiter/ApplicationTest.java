package sample.spring.security.junitjupiter;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import sample.spring.security.Application;


@SpringBootTest(classes = Application.class)
@java.lang.SuppressWarnings("squid:S2699")
@ActiveProfiles("multixsuaa") // properties are provided with /resources/application-multixsuaa.yml
class ApplicationTest {

	@Test
	void whenSpringContextIsBootstrapped_thenNoExceptions() {
	}
}
