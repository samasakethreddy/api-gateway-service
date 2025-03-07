package com.saketh.pg_api_gateway.routes;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.server.mvc.filter.CircuitBreakerFilterFunctions;
import org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.function.*;

import java.net.URI;

import static org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions.route;

@Configuration
@RestController
public class Routes {

    @Value("${tenantService.service.url}")
    private String tenantServiceUrl;

    @Value("${roomService.service.url}")
    private String roomServiceUrl;

    @Value("${dueService.service.url}")
    private String dueServiceUrl;

    @GetMapping("/test")
    String test() {
        return "Hello World!";
    }

    private static HandlerFunction<ServerResponse> forwardWithHeaders(String targetUrl) {
        return request -> {
            // Extract Authorization header
            String authHeader = request.headers().firstHeader(HttpHeaders.AUTHORIZATION);
            String userRoles = request.headers().firstHeader("roles");  // Extract roles if available

            // Create a new request builder and add headers conditionally
            ServerRequest.Builder newRequest = ServerRequest.from(request);

            if (authHeader != null) {
                newRequest.header(HttpHeaders.AUTHORIZATION, authHeader);
            }
            if (userRoles != null) {
                newRequest.header("roles", userRoles);
            }

            // Forward request to the target URL with modified headers
            return HandlerFunctions.http(targetUrl).handle(newRequest.build());
        };
    }


    @Bean
    public RouterFunction<ServerResponse> tenantServiceRoute() {
        return route("tenant_service")
                .route(RequestPredicates.path("/api/tenants/**"), forwardWithHeaders(tenantServiceUrl))
                .filter(CircuitBreakerFilterFunctions.circuitBreaker("tenantServiceCircuitBreaker",
                        URI.create("forward:/fallbackRoute")))
                .build();
    }

    @Bean
    public RouterFunction<ServerResponse> roomServiceRoute() {
        return route("room_service")
                .route(RequestPredicates.path("/api/room/**"), forwardWithHeaders(roomServiceUrl))
                .filter(CircuitBreakerFilterFunctions.circuitBreaker("roomServiceCircuitBreaker",
                        URI.create("forward:/fallbackRoute")))
                .build();
    }

    @Bean
    public RouterFunction<ServerResponse> dueServiceRoute() {
        return route("due_service")
                .route(RequestPredicates.path("/api/dues/**"), forwardWithHeaders(dueServiceUrl))
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
