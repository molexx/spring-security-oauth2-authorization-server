package oauth.server.sample;

import java.time.Duration;

import com.github.benmanes.caffeine.cache.Caffeine;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.Cache;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


/**
 * Uses Caffeine to create a local in-memory cache.
 * 
 * Real-world applications that run with multiple nodes will want to replace this with a distributed cache e.g. Redis
 * 
 * 
 */
@Configuration
@ConditionalOnProperty(prefix = "io.zheaux.springsecurity", name = {"enabled"}, havingValue = "true")
class LocalCacheConfig {
	
	@Bean
	Cache accessTokenCache() {
		return new CaffeineCache("access_tokens", Caffeine.newBuilder()
				.expireAfterWrite(Duration.ofHours(1))
				.maximumSize(1_000_000)
				.build());
	}

	@Bean
	Cache refreshTokenCache() {
		return new CaffeineCache("refresh_tokens", Caffeine.newBuilder()
				.expireAfterWrite(Duration.ofDays(1))
				.maximumSize(1_000_000)
				.build());
	}

	@Bean
	Cache authorizationCodeCache() {
		return new CaffeineCache("authorization_code", Caffeine.newBuilder()
				.expireAfterWrite(Duration.ofMinutes(2))
				.maximumSize(1_000_000)
				.build());
	}

}
