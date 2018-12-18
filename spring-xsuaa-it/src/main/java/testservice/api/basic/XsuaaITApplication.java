package testservice.api.basic;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Profile;

@Profile({ "test.api.basic" })
@SpringBootApplication
public class XsuaaITApplication {

	public static void main(String[] args) {
		SpringApplication.run(XsuaaITApplication.class, args);
	}
}
