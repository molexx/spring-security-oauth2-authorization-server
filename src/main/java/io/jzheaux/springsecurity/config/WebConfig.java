package io.jzheaux.springsecurity.config;

import java.util.List;

import io.jzheaux.springsecurity.NimbusRequestResponseHandler;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.HandlerMethodReturnValueHandler;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@ConditionalOnProperty(prefix = "io.zheaux.springsecurity", name = {"enabled"}, havingValue = "true")
class WebConfig implements WebMvcConfigurer {
	NimbusRequestResponseHandler handler = new NimbusRequestResponseHandler();

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
		resolvers.add(handler);
	}

	@Override
	public void addReturnValueHandlers(List<HandlerMethodReturnValueHandler> handlers) {
		handlers.add(handler);
	}
}
