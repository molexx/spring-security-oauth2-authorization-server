package io.jzheaux.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Map;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.Customizer.withDefaults;


/**
 * Gives access to
 *   {mvcPrefix}/introspect fpr callers with hasRole("CLIENT")
 *   {mvcPrefix}/.well-known/openid-configuration to all
 *   POST to {mvcPrevix}/token where param grant_type is in the configured OAuth client's ClientMetadata.grantTypes
 * 
 * enables BASIC security - client's secret is sent in header
 * disables crsf
 * disables sessions
 * 
 * Injects a UserDetailsService bean named "oauthServerClientDetailsService" which must be provided by the application
 * 
 */
@Configuration
@ConditionalOnProperty(prefix = "io.zheaux.springsecurity", name = {"enabled"}, havingValue = "true")
@Order(101)
//@EnableWebSecurity
public class ClientEndpoints extends WebSecurityConfigurerAdapter {
    @Autowired
    @Qualifier("oauthServerClientDetailsService")
    UserDetailsService oauthServerClientDetailsService;


    @Value("${io.zheaux.springsecurity.mvcprefix}")
    String mvcPrefix;


    /**
     * used by UserController when it calls ProviderManager.authenticate()
     */
    private DaoAuthenticationProvider basicAuthProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(oauthServerClientDetailsService);
        //authProvider.setPasswordEncoder(passwordEncoder());
        //authProvider.setHideUserNotFoundExceptions(false);
        return authProvider;
    }

    /*
    //don't make this private! Injected into UserService
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();  //will internally generate a random salt using 10 rounds
    }
    */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(basicAuthProvider());
        //auth.authenticationProvider(rememberMeAuthenticationProvider());
    }

    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        System.out.println("ClientEndpoints.configure(): http: '" + http + "'");

        http.requestMatchers(r -> r.mvcMatchers(mvcPrefix + "/token",
                mvcPrefix + "/introspect",
                mvcPrefix + "/.well-known/openid-configuration"))
                .authorizeRequests(a -> {
                    a.requestMatchers(new GrantTypeMatcher(mvcPrefix)).access("hasRole(#type)");
                    a.mvcMatchers(POST, mvcPrefix + "/introspect").hasRole("CLIENT");
                    a.mvcMatchers(GET, mvcPrefix + "/.well-known/openid-configuration").permitAll();
                    a.anyRequest().denyAll();
                })
                .httpBasic(withDefaults())  //needed so client app can 'login' with its secret to access /token
                .userDetailsService(this.oauthServerClientDetailsService)
                .sessionManagement().disable()
                //.httpBasic().disable()
                //.formLogin().disable()
                .csrf().disable()
        ;
    }

    private static class GrantTypeMatcher implements RequestMatcher {
        //private final String mvcPrefix;
        private final AntPathRequestMatcher matcher;

        GrantTypeMatcher(String mvcPrefix) {
            //this.mvcPrefix = mvcPrefix;
            matcher = new AntPathRequestMatcher(mvcPrefix + "/token", "POST");
        }


        /**
         * returns true if the request is a POST to "{mvcPrefix}/token"
         * 
         * @param request
         * @return
         */
        @Override
        public boolean matches(HttpServletRequest request) {
            return this.matcher.matches(request);
        }

        @Override
        public MatchResult matcher(HttpServletRequest request) {
            Map<String, String> variables = Collections.singletonMap("type", request.getParameter("grant_type"));
            return MatchResult.match(variables);
        }
    }
}
