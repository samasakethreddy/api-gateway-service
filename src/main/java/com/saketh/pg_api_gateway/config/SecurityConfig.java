package com.saketh.pg_api_gateway.config;

import com.saketh.pg_api_gateway.repository.UserRepository;
import com.saketh.pg_api_gateway.services.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.context.annotation.RequestScope;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    // Publicly accessible endpoints (No authentication required)
    private static final String[] PUBLIC_URLS = {
            "/api/users/login",
            "/api/users/register",
            "/logout",
            "/api/docs/**",   // Swagger docs (optional)
            "/api/public/**"  // Public API endpoints (optional)
    };


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, UserRepository userRepository, AuthHolder authHolder) throws Exception {
        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_URLS).permitAll()
                        .anyRequest().authenticated()
                )
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                )
                // Add custom authorization filter after OAuth2 JWT token filter (BearerTokenAuthenticationFilter)
                .addFilterAfter(
                        new JwtUserAuthorizationFilter(userRepository, authHolder),
                        BearerTokenAuthenticationFilter.class
                )
                .build();
    }


    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfig = new CorsConfiguration();

        // Specify allowed origins (restrict in production)
        corsConfig.setAllowedOrigins(List.of(
                "http://localhost:3000", // React frontend
                "http://localhost:4200", // Angular frontend
                "https://your-production-domain.com", // Production domain
                "https://web.postman.co/*"
        ));

        // Allowed HTTP methods
        corsConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));

        // Allowed headers
        corsConfig.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
                "Origin",
                "X-User-Roles"
        ));

        corsConfig.setAllowCredentials(true); // Allow sending cookies & credentials
        corsConfig.setMaxAge(3600L); // Cache CORS preflight requests for 1 hour

        // Apply configuration to all paths
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return source;
    }

    @Bean
    public AuthHolder authHolder() {
        return new AuthHolder();
    }

}
