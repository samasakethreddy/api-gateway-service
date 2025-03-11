package com.saketh.pg_api_gateway.controller;

import com.saketh.pg_api_gateway.services.KeycloakAdminService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final KeycloakAdminService keycloakAdminService;

    public UserController(KeycloakAdminService keycloakUserService) {
        this.keycloakAdminService = keycloakUserService;
    }

    @PostMapping("/register/owner")
    public ResponseEntity<String> registerOwner(@RequestBody Map<String, String> userDetails, HttpServletRequest request) {
        userDetails.put("role", "OWNER"); // Ensure role is set
        return keycloakAdminService.createOwner(userDetails, request);
    }

    @PostMapping("/register/tenant")
    @PreAuthorize("hasRole('OWNER')")
    public ResponseEntity<String> registerTenant(@RequestBody Map<String, String> userDetails, HttpServletRequest request) {
        userDetails.put("role", "TENANT"); // Ensure role is set
        return keycloakAdminService.createTenant(userDetails, request);
    }


    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> loginUser(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        // Basic input validation
        if (username == null || password == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Missing username or password",
                    "status", 400
            ));
        }

        return keycloakAdminService.loginUser(username, password);
    }



    @PostMapping("/logout")
    public ResponseEntity<String> logoutUser(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refresh_token");

        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.badRequest().body("Refresh token is required");
        }

        return keycloakAdminService.logoutUser(refreshToken);
    }


    @PostMapping("/validate-token")
    public ResponseEntity<Map<String, Object>> validateToken(@RequestBody Map<String, String> tokenRequest) {
        String token = tokenRequest.get("token");

        if (token == null || token.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Token is required",
                    "status", 400
            ));
        }

        return keycloakAdminService.validateToken(token);
    }
}
