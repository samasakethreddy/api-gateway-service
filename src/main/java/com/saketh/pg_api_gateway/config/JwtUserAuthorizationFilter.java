package com.saketh.pg_api_gateway.config;

import com.saketh.pg_api_gateway.entity.User;
import com.saketh.pg_api_gateway.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class JwtUserAuthorizationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtUserAuthorizationFilter.class);

    private final UserRepository userRepository;

    public JwtUserAuthorizationFilter(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!(authentication instanceof JwtAuthenticationToken jwtAuthToken)) {
            logger.debug("Authentication is not a JwtAuthenticationToken, skipping custom role mapping");
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Jwt jwt = jwtAuthToken.getToken();
            String email = jwt.getClaimAsString("email");

            logger.debug("Jwt claim email: {}", email);

            if (email == null) {
                // Try preferred_username if email is not available
                email = jwt.getClaimAsString("preferred_username");
                if (email == null) {
                    logger.warn("No user email or username found in Keycloak JWT");
                    filterChain.doFilter(request, response);
                    return;
                }
            }

            logger.debug("Processing JWT for user: {}", email);

            // Fetch user from DB
            User user = userRepository.findByEmail(email).orElse(null);
            if (user == null) {
                logger.warn("User not found in database: {}", email);
                filterChain.doFilter(request, response);
                return;
            }

            // Get existing authorities from the token
            Collection<GrantedAuthority> authorities = new ArrayList<>(jwtAuthToken.getAuthorities());

            // Add database roles
            List<SimpleGrantedAuthority> dbAuthorities = user.getRoles().stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                    .collect(Collectors.toList());

            authorities.addAll(dbAuthorities);

            // Create a new JWT authentication with combined authorities
            JwtAuthenticationToken newToken = new JwtAuthenticationToken(
                    jwt,
                    authorities,
                    jwtAuthToken.getName()
            );

            // Set authentication in SecurityContext
            SecurityContextHolder.getContext().setAuthentication(newToken);
            logger.info("User {} authorized with combined roles: {}", email, authorities);
        } catch (Exception e) {
            logger.error("Error processing JWT authentication", e);
        }

        filterChain.doFilter(request, response);
    }
}