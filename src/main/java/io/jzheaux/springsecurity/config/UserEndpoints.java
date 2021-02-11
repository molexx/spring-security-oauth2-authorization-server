package io.jzheaux.springsecurity.config;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.Customizer.withDefaults;

//@EnableWebSecurity
//@Configuration
//@Order(102)
public class UserEndpoints extends WebSecurityConfigurerAdapter {

	@Value("${io.zheaux.springsecurity.mvcprefix}")
	String mvcPrefix;

	public static CorsConfigurationSource ccs = new CorsConfigurationSource() {
		@Override
		public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
			CorsConfiguration cc = new CorsConfiguration();
			cc.addAllowedHeader(CorsConfiguration.ALL);
			cc.addAllowedMethod(CorsConfiguration.ALL);
			cc.addAllowedOrigin(CorsConfiguration.ALL);
			cc.setAllowCredentials(true);
			return(cc);
		}
	};

	/**
	 * URL the user-agent will be redirected to when unauthenticated. For use when Spring Security's loginForm is not used.
	 */
	//@Value("${io.zheaux.springsecurity.loginurl}")
	//String loginUrl;


	/*
	private final AuthenticationEntryPoint aep = new AuthenticationEntryPoint() {
		@Override
		public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
			System.out.println("authenticationEntryPoint called, req URI: " + httpServletRequest.getRequestURI());
			if (loginUrl != null) {
				httpServletResponse.sendRedirect(loginUrl 
								+ "?scope=" + httpServletRequest.getParameter("scope") 
								//+ "&request_uri=" + httpServletRequest.getParameter("request_uri")
								+ "&redirect_uri=" + httpServletRequest.getParameter("redirect_uri")
								+ "&state=" + httpServletRequest.getParameter("state")
								+ "&client_id=" + httpServletRequest.getParameter("client_id")
				);
			}
		}
	};*/
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		System.out.println("UserEndpoints.configure(): http: '" + http + "'");
		//OAuth2ResourceServerConfigurer orsc = OAuth2ResourceServerConfigurer::opaqueToken;
		//http.oauth2ResourceServer()
		
http
				//.formLogin().disable()
				//.authorizeRequests().antMatchers("/login").anonymous().and()
				//.formLogin(withDefaults()).cors().configurationSource(ccs).and()
				//.formLogin().loginPage("http://localhost:8000/login.html").and()
				//.requestMatchers(r -> r.antMatchers(mvcPrefix + "/**"))
				//.cors()//.configurationSource(CorsConfiguration.ALL)
				//	.configurationSource(ccs).and()
				/*.exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {
					@Override
					public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
						System.out.println("UserEndpoints root second accessDeniedHandler called, req path: " + httpServletRequest.getPathInfo());
					}
				}).and()*/
				/*.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> {
					httpSecurityExceptionHandlingConfigurer.accessDeniedHandler(new AccessDeniedHandler() {
						@Override
						public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
							System.out.println("UserEndpoints root accessDeniedHandler called, req path: " + httpServletRequest.getPathInfo());
						}
					});
				})*/
.authorizeRequests(a -> {
	a.mvcMatchers(GET, mvcPrefix + "/userinfo").hasAuthority("SCOPE_profile");
	//a.anyRequest().authenticated();
})
				 /*.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> {
					httpSecurityExceptionHandlingConfigurer.accessDeniedHandler(new AccessDeniedHandler() {
						@Override
						public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
							System.out.println("UserEndpoints authorizeRequests's accessDeniedHandler called, req path: " + httpServletRequest.getPathInfo());
						}
					});
				})*/
				//.formLogin(withDefaults())//.cors().configurationSource(ccs).and()
.oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken)//.exceptionHandling().authenticationEntryPoint(aep).and()
				/*.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> {
					httpSecurityExceptionHandlingConfigurer.accessDeniedHandler(new AccessDeniedHandler() {
						@Override
						public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
							System.out.println("UserEndpoints oauth2ResourceServer's accessDeniedHandler called, req path: " + httpServletRequest.getPathInfo());
						}
					});
				})*/
				//.csrf().disable()
				/*().exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {
					@Override
					public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
						System.out.println("UserEndpoints end second accessDeniedHandler called, req path: " + httpServletRequest.getPathInfo());
					}
				})*/
		;
	}
	
	/*
	@Bean
	AuthenticationManager endUserAuthenticationManager(UserDetailsService userDetailsService) throws Exception {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(userDetailsService);
		return provider::authenticate;
	}*/
	
	/*
	@Bean
	@Override
	public UserDetailsService userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withDefaultPasswordEncoder()
						.username("user")
						.password("password")
						.roles("USER")
						.build());
	}*/
}

