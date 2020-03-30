package sample.spring.xsuaa.junitjupiter;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import sample.spring.xsuaa.Application;

@SpringBootTest(classes = Application.class)
public class ApplicationTest {

	@Test
	public void whenSpringContextIsBootstrapped_thenNoExceptions() {
	}
}
