package oauth.server.sample;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Component
@Order(300) //if this is last then nothing requires auth. If this is first then everything requires auth.
public class SecurityConfig extends WebSecurityConfigurerAdapter  {

    @Value("${io.zheaux.springsecurity.mvcprefix}")
    String oauthPrefix;



    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        System.out.println("SecurityConfig.configure(): http: '" + http + "'");
        http
                .authorizeRequests(a -> {
                    a.mvcMatchers(GET, oauthPrefix + "/userinfo").hasAuthority("SCOPE_profile");
                    //a.anyRequest().authenticated();
                })
                
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken)//.exceptionHandling().authenticationEntryPoint(aep).and()
                
                .authorizeRequests().anyRequest().authenticated().and()//.formLogin();
                //.antMatcher("/**").authorizeRequests()
                //.authorizeRequests().anyRequest().authenticated().and()
                /*.authorizeRequests(a -> {
                    //a.mvcMatchers(GET, mvcPrefix + "/userinfo").hasAuthority("SCOPE_profile");
                    a.anyRequest().authenticated();
                })*/
                /*.authorizeRequests(a -> {
                    a.mvcMatchers(GET, "irrelevant").hasAuthority("SCOPE_profile");
                    a.anyRequest().authenticated();
                })*/
                .formLogin(withDefaults())//.and()
                //.httpBasic()
                ;
        //super.configure();
    }
    
    
    /**
     * URL the user-agent will be redirected to when unauthenticated. For use when Spring Security's loginForm is not used.
     */
    @Value("${io.zheaux.springsecurity.loginurl}")
    private String loginUrl;
    
    
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
    };


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
    
}
