package com.saketh.pg_api_gateway.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.stream.Collectors;

public class RoleInjectingFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(RoleInjectingFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var authentication = SecurityContextHolder.getContext().getAuthentication();
        logger.info("authentication object: {}", authentication);

        if (authentication != null && authentication.getPrincipal() instanceof UserDetails userDetails) {

            String roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(","));

            logger.info("Authenticated user: {} with roles: {}", userDetails.getUsername(), roles);

            // Wrap request and add custom header
            HttpServletRequest wrappedRequest = new HttpServletRequestWrapper(request) {
                @Override
                public String getHeader(String name) {
                    if ("X-User-Roles".equalsIgnoreCase(name)) {
                        return roles;
                    }
                    return super.getHeader(name);
                }
            };

            filterChain.doFilter(wrappedRequest, response);
            return;
        }

        logger.debug("No authenticated user found in SecurityContext.");
        filterChain.doFilter(request, response);
    }
}
