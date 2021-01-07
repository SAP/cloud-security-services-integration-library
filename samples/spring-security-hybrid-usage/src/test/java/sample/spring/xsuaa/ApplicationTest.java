package sample.spring.xsuaa;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = Application.class)
@java.lang.SuppressWarnings("squid:S2699")
//@TestPropertySource are provided with /resources/application.yml
class ApplicationTest {

	@Test
	void whenSpringContextIsBootstrapped_thenNoExceptions() {
	}
}