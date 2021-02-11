package io.jzheaux.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * Requires authenticated access to oauthPrefix path, and allows access via an oauth2 opaqueToken
 * 
 * If an optional AuthenticationEntryPoint @Bean named 'oauthServerAuthenticationEntryPoint' is configured this is used to handle all unauthenticated requests to {oauthPrefix}/**.
 * 
 */
@Order(102)
@Configuration
@ConditionalOnProperty(prefix = "io.zheaux.springsecurity", name = {"enabled"}, havingValue = "true")
@ConditionalOnMissingBean(OAuthServerSecurityConfig.class)  //allow overriding by application
public class OAuthServerSecurityConfig //{

    /*
    @Order(102)
    @Configuration
    public static class Secure */ extends WebSecurityConfigurerAdapter {

        @Value("${io.zheaux.springsecurity.mvcprefix}")
        String oauthPrefix;


        @Autowired(required = false)
        private AuthenticationEntryPoint oauthServerAuthenticationEntryPoint;


        @Override
        protected void configure(HttpSecurity http) throws Exception {
            System.out.println("OAuthServerSecurityConfig.Secure.configure(): http: '" + http + "'");
            
            
            http = http
                    //.requestMatchers(r -> r.antMatchers(oauthPrefix + "/**"))
                    .requestMatchers().antMatchers(oauthPrefix + "/**").and()
                    .oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken)
                    .authorizeRequests().anyRequest().authenticated().and()
            ;
            
            if (oauthServerAuthenticationEntryPoint != null) {
                http = http.exceptionHandling().authenticationEntryPoint(oauthServerAuthenticationEntryPoint).and();
            }
        }
    }



/*
    @Order(103)
    @Configuration
    @ConditionalOnBean(name="oauthServerAuthenticationEntryPoint")
    public static class RedirectToLogin extends WebSecurityConfigurerAdapter {

        @Value("${io.zheaux.springsecurity.mvcprefix}")
        String oauthPrefix;

        @Autowired(required = false)
        private AuthenticationEntryPoint oauthServerAuthenticationEntryPoint;


        @Override
        protected void configure(HttpSecurity http) throws Exception {
            System.out.println("OAuthServerSecurityConfig.RedirectToLogin.configure(): http: '" + http + "', oauthServerAuthenticationEntryPoint: " + oauthServerAuthenticationEntryPoint);

            http.antMatcher(oauthPrefix + "/authorise**").authorizeRequests()
                    .exceptionHandling().authenticationEntryPoint(oauthServerAuthenticationEntryPoint).and();

        }
    }
*/
//}
