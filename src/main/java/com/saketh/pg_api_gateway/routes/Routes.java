package com.saketh.pg_api_gateway.routes;

import com.saketh.pg_api_gateway.config.AuthHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.server.mvc.filter.CircuitBreakerFilterFunctions;
import org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.function.*;

import java.net.URI;
import java.util.stream.Collectors;

import static org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions.route;

@Configuration
@RestController
public class Routes {

    private static final Logger logger = LoggerFactory.getLogger(Routes.class);

    private final AuthHolder authHolder;

    @Value("${tenantService.service.url}")
    private String tenantServiceUrl;

    @Value("${roomService.service.url}")
    private String roomServiceUrl;

    @Value("${dueService.service.url}")
    private String dueServiceUrl;

    public Routes(AuthHolder authHolder) {
        this.authHolder = authHolder;
    }

    @GetMapping("/test")
    String test() {
        return "Hello World!";
    }

    @GetMapping("/checkRoles")
    public ResponseEntity<?> checkRoles() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return ResponseEntity.ok(authentication.getAuthorities());
    }

    // 🔥 Remove static keyword so it can access authHolder instance
    private static HandlerFunction<ServerResponse> forwardWithHeaders(String targetUrl, AuthHolder authHolder) {

        return request -> {
            // Extract Authorization header
            String authHeader = request.headers().firstHeader(HttpHeaders.AUTHORIZATION);

            // Get authentication details
            Authentication authentication = authHolder.getAuthentication();

            logger.info("AuthHolder Authentication: {}", authentication);

            // Extract user roles
            String userRoles = (authentication != null)
                    ? authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(","))
                    : null;

            logger.info("User Roles: {}", userRoles);

            // Create a new request builder and add headers conditionally
            ServerRequest.Builder newRequest = ServerRequest.from(request);
            if (authHeader != null) {
                newRequest.header(HttpHeaders.AUTHORIZATION, authHeader);
            }
            if (userRoles != null) {
                newRequest.header("X-User-Roles", userRoles);
            }

            // Forward request to the target URL with modified headers
            return HandlerFunctions.http(targetUrl).handle(newRequest.build());
        };
    }

    @Bean
    public RouterFunction<ServerResponse> tenantServiceRoute() {
        return route("tenant_service")
                .route(RequestPredicates.path("/api/tenants/**"), forwardWithHeaders(tenantServiceUrl, authHolder))
                .filter(CircuitBreakerFilterFunctions.circuitBreaker("tenantServiceCircuitBreaker",
                        URI.create("forward:/fallbackRoute")))
                .build();
    }

    @Bean
    public RouterFunction<ServerResponse> roomServiceRoute() {
        return route("room_service")
                .route(RequestPredicates.path("/api/room/**"), forwardWithHeaders(roomServiceUrl, authHolder))
                .filter(CircuitBreakerFilterFunctions.circuitBreaker("roomServiceCircuitBreaker",
                        URI.create("forward:/fallbackRoute")))
                .build();
    }

    @Bean
    public RouterFunction<ServerResponse> dueServiceRoute() {
        return route("due_service")
                .route(RequestPredicates.path("/api/dues/**"), forwardWithHeaders(dueServiceUrl, authHolder))
                .filter(CircuitBreakerFilterFunctions.circuitBreaker("dueServiceCircuitBreaker",
                        URI.create("forward:/fallbackRoute")))
                .build();
    }

    @Bean
    public RouterFunction<ServerResponse> fallbackRoute() {
        return route("fallbackRoute")
                .GET("/fallbackRoute", request -> ServerResponse.status(HttpStatus.SERVICE_UNAVAILABLE)
                        .body("Service Unavailable, please try again later"))
                .build();
    }
}
