package oauth.server.sample;

import io.jzheaux.springsecurity.OAuth2AuthorizationServerController;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;


@SpringBootApplication
@ComponentScan(basePackageClasses = {OAuth2AuthorizationServerController.class, SampleClientDetailsService.class})
public class SampleAuthorizationServer {
	public static void main(String[] args) {
		SpringApplication.run(SampleAuthorizationServer.class, args);
	}


	@Bean
	public UserDetailsService userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withDefaultPasswordEncoder()
						.username("user")
						.password("password")
						.roles("USER")
						.build());
	}
	
	
	@Bean
	AuthenticationManager endUserAuthenticationManager(UserDetailsService userDetailsService) throws Exception {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(userDetailsService);
		return provider::authenticate;
	}
}
