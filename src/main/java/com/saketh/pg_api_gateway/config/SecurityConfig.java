package com.saketh.pg_api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Configurable free access URLs
    private final String[] PUBLIC_URLS = {
            "/api/users/login",
            "/api/users/login/**",
            "/logout",
            "/logout/**",
            "/api/users/register"
    };

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                // Disable CSRF protection for stateless REST API
                .csrf(csrf -> csrf.disable())

                // Configure session management as stateless
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Configure authorization rules
                .authorizeHttpRequests(authorize -> authorize
                        // Permit access to public URLs
                        .requestMatchers(PUBLIC_URLS).permitAll()

                        // Require authentication for all other requests
                        .anyRequest().authenticated()
                )

                // Enable CORS
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Configure OAuth2 Resource Server with JWT
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(Customizer.withDefaults())
                )

                .build();
    }


    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<String> roles = (Collection<String>) jwt.getClaimAsMap("realm_access").get("roles");
            return  roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                    .collect(Collectors.toList());
        });
        return jwtAuthenticationConverter;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();

        // Allowed origins (replace with your specific origins in production)
        corsConfiguration.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",  // React frontend
                "http://localhost:4200",  // Angular frontend
                "https://your-production-domain.com",
                "*"
        ));

        // Allowed HTTP methods
        corsConfiguration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"
        ));

        // Allowed headers
        corsConfiguration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
                "Origin"
        ));

        // Enable credentials
        corsConfiguration.setAllowCredentials(true);

        // Max age for CORS preflight request
        corsConfiguration.setMaxAge(3600L);

        // Create CORS configuration source
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);

        return source;
    }

}