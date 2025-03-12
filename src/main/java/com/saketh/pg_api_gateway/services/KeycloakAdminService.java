package com.saketh.pg_api_gateway.services;

import com.saketh.pg_api_gateway.entity.Owner;
import com.saketh.pg_api_gateway.entity.Role;
import com.saketh.pg_api_gateway.entity.Tenant;
import com.saketh.pg_api_gateway.entity.User;
import com.saketh.pg_api_gateway.repository.OwnerRepository;
import com.saketh.pg_api_gateway.repository.RoleRepository;
import com.saketh.pg_api_gateway.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class KeycloakAdminService {

    private static final Logger logger = LoggerFactory.getLogger(KeycloakAdminService.class);

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private RestClient restClient;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OwnerRepository ownerRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Value("${tenantService.service.url}")
    private String tenantServiceUrl;

    @Value("${keycloak.server-url}")
    private String KEYCLOAK_SERVER_URL;

    @Value("${keycloak.realm}")
    private String REALM;

    @Value("${keycloak.client-id}")
    private String CLIENT_ID;

    @Value("${keycloak.client-secret}")
    private String CLIENT_SECRET;


    /**
     * Obtain admin access token for administrative operations
     *
     * @return Access token string
     */
    private String getAdminAccessToken() {
        String tokenUrl = KEYCLOAK_SERVER_URL + "/realms/master/protocol/openid-connect/token";

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", "admin-cli");
            body.add("grant_type", "password");
            body.add("username", "saketh_sama");
            body.add("password", "Saketh@123");

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

            if (response.getBody() != null && response.getBody().containsKey("access_token")) {
                return (String) response.getBody().get("access_token");
            }

            throw new RuntimeException("Failed to obtain admin access token");
        } catch (Exception e) {
            throw new RuntimeException("Error obtaining admin access token", e);
        }
    }

    /**
     * Creates a new tenant in the system.
     * 1. Retrieves the owner's details from the JWT token.
     * 2. Validates user input.
     * 3. Sends tenant data to the tenant service.
     * 4. Calls `createUser` to register the tenant in Keycloak.
     *
     * @param userDetails User-provided tenant details.
     * @param request     HTTP request containing the Authorization header.
     * @return ResponseEntity<String> indicating success or failure.
     */
    public ResponseEntity<String> createTenant(Map<String, String> userDetails, HttpServletRequest request) {
        try {
            // Extract JWT authentication and fetch owner email
            Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            String ownerEmail = jwt.getClaimAsString("email");

            // Retrieve owner from the database
            Owner owner = ownerRepository.findByEmail(ownerEmail)
                    .orElseThrow(() -> new RuntimeException("Owner not found with email: " + ownerEmail));

            // Validate required fields in userDetails
            if (!validateTenantFields(userDetails)) {
                return ResponseEntity.badRequest().body("Missing or invalid tenant details.");
            }

            // Extract Authentication object
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            // Extract user roles
            String userRoles = (authentication != null)
                    ? authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(","))
                    : null;

            // Extract Authorization token
            String authToken = request.getHeader("Authorization");
            if (authToken == null || authToken.isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Authorization header is required.");
            }

            // Map user details to Tenant DTO
            Tenant tenant = Tenant.builder()
                    .ownerId(owner.getEmail()) // Owner email is used as ownerId
                    .tenantName(userDetails.get("firstName") + " " + userDetails.get("lastName"))
                    .tenantAge(Integer.parseInt(userDetails.get("age")))
                    .roomId(Integer.parseInt(userDetails.get("roomId")))
                    .aadharId(userDetails.get("aadharId"))
                    .email(userDetails.get("email"))
                    .phoneNumber(userDetails.get("phoneNumber"))
                    .joinDate(LocalDate.parse(userDetails.get("joinDate"))) // Parse date
                    .build();

            // Log Tenant Data (For Debugging)
            logger.info("Sending Tenant Data: {}", tenant);

            // Send tenant data to tenant service in request body
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(authToken);

            if (userRoles != null) {
                headers.add("X-User-Roles", userRoles); // Send user roles to tenant service
                logger.info("Roles Added");
            }

            // Create HTTP Entity with Tenant as Body
            HttpEntity<Tenant> tenantRequestEntity = new HttpEntity<>(tenant, headers);

            logger.info("tenantRequestEntity created");

//            // Make API Call to Tenant Service
//            ResponseEntity<String> tenantResponse = restTemplate.exchange(
//                    tenantServiceUrl + "/api/tenants",
//                    HttpMethod.POST,
//                    tenantRequestEntity,
//                    String.class
//            );
//
//            logger.info("Tenant Service called");
//
////             Check if tenant creation was successful
//            if (!tenantResponse.getStatusCode().is2xxSuccessful()) {
//                logger.error("Tenant Service Response: {}", tenantResponse.getBody());
//                return ResponseEntity.status(tenantResponse.getStatusCode()).body("Tenant creation failed.");
//            }
//
//            // Log Success
//            logger.info("Tenant successfully created in Tenant Service.");
//
//            // Register user in Keycloak
//            return createUser(userDetails, request);


            // Send tenant data to tenant service using RestClient
            ResponseEntity<String> tenantResponse = restClient.post()
                    .uri(tenantServiceUrl + "/api/tenants")
                    .header(HttpHeaders.AUTHORIZATION, authToken)
                    .body(tenant)
                    .retrieve()
                    .toEntity(String.class);

            // Check if tenant creation was successful
            if (!tenantResponse.getStatusCode().is2xxSuccessful()) {
                logger.error("Tenant Service Response: {}", tenantResponse.getBody());
                return ResponseEntity.status(tenantResponse.getStatusCode()).body("Tenant creation failed.");
            }

            // Log success
            logger.info("Tenant successfully created in Tenant Service.");

            // Register user in Keycloak
            return createUser(userDetails, request);

        } catch (Exception e) {
            logger.error("Error creating tenant: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error creating tenant: " + e);
        }
    }


    /**
     * Creates an owner account.
     * 1. Validates input.
     * 2. Saves owner details to the database.
     * 3. Calls `createUser` to register the owner in Keycloak.
     *
     * @param userDetails User-provided owner details.
     * @param request     HTTP request.
     * @return ResponseEntity<String> indicating success or failure.
     */
    public ResponseEntity<String> createOwner(Map<String, String> userDetails, HttpServletRequest request) {
        try {
            if (!validateOwnerFields(userDetails)) {
                return ResponseEntity.badRequest().body("Missing required owner details.");
            }

            // Extract user details
            String email = userDetails.get("email");

            // Save owner details in the database
            Owner owner = Owner.builder()
                    .name(email)
                    .email(email)
                    .build();

            ownerRepository.save(owner);

            // Register owner in Keycloak
            return createUser(userDetails, request);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error creating owner: " + e.getMessage());
        }
    }

    /**
     * Creates a user in Keycloak.
     * 1. Validates input fields.
     * 2. Sends a request to Keycloak's user management API.
     * 3. Stores user data in the local database.
     *
     * @param userDetails User-provided details.
     * @param request     HTTP request.
     * @return ResponseEntity<String> indicating success or failure.
     */
    public ResponseEntity<String> createUser(Map<String, String> userDetails, HttpServletRequest request) {
        try {
            String adminToken = getAdminAccessToken();

            if (!validateUserFields(userDetails)) {
                return ResponseEntity.badRequest().body("Missing required user details.");
            }

            // Prepare user creation payload for Keycloak
            Map<String, Object> userRepresentation = Map.of(
                    "username", userDetails.get("email"),
                    "email", userDetails.get("email"),
                    "enabled", true,
                    "firstName", userDetails.get("firstName"),
                    "lastName", userDetails.get("lastName"),
                    "credentials", List.of(Map.of(
                            "type", "password",
                            "value", userDetails.get("password"),
                            "temporary", false
                    ))
            );

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(adminToken);

            HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(userRepresentation, headers);
            ResponseEntity<String> response = restTemplate.exchange(
                    KEYCLOAK_SERVER_URL + "/admin/realms/" + REALM + "/users",
                    HttpMethod.POST,
                    requestEntity,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                String userId = getKeycloakUserId(userDetails.get("email"), adminToken);

                if (userId == null) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body("Failed to retrieve Keycloak user ID.");
                }

                saveUserToDatabase(userId, userDetails.get("email"), userDetails.get("email"),
                        userDetails.get("firstName"), userDetails.get("lastName"),
                        userDetails.get("role"));
                return ResponseEntity.ok("User created successfully.");
            }

            return ResponseEntity.status(response.getStatusCode()).body("User creation failed.");
        } catch (HttpClientErrorException e) {
            return ResponseEntity.status(e.getStatusCode())
                    .body("User creation failed: " + e.getResponseBodyAsString());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An unexpected error occurred: " + e.getMessage());
        }
    }

    // Helper functions for input validation
    private boolean validateUserFields(Map<String, String> userDetails) {
        return userDetails.containsKey("email") && userDetails.containsKey("password") &&
                userDetails.containsKey("firstName") && userDetails.containsKey("lastName") &&
                userDetails.containsKey("role");
    }

    private boolean validateTenantFields(Map<String, String> userDetails) {
        return userDetails.containsKey("firstName") && userDetails.containsKey("lastName") &&
                userDetails.containsKey("age") && userDetails.containsKey("roomId") &&
                userDetails.containsKey("aadharId") && userDetails.containsKey("email") &&
                userDetails.containsKey("phoneNumber") && userDetails.containsKey("joinDate");
    }

    private boolean validateOwnerFields(Map<String, String> userDetails) {
        return userDetails.containsKey("email");
    }

    /**
     * Authenticate user and obtain access token
     *
     * @param username User's username
     * @param password User's password
     * @return Authentication response with tokens
     */
    public ResponseEntity<Map<String, Object>> loginUser(String username, String password) {
        String tokenUrl = KEYCLOAK_SERVER_URL + "/realms/" + REALM + "/protocol/openid-connect/token";
//        http://localhost:8180/realms/pg-management-realm/protocol/openid-connect/token
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", CLIENT_ID);
            body.add("client_secret", CLIENT_SECRET);
            body.add("grant_type", "password");
            body.add("username", username);
            body.add("password", password);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(
                    tokenUrl,
                    request,
                    Map.class
            );

            return ResponseEntity
                    .status(response.getStatusCode())
                    .body(response.getBody());

        } catch (HttpClientErrorException e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Authentication failed");
            errorResponse.put("status", e.getStatusCode().value());

            return ResponseEntity
                    .status(e.getStatusCode())
                    .body(errorResponse);
        }
    }


    // Used to logout user
    public ResponseEntity<String> logoutUser(String refreshToken) {
        String logoutUrl = KEYCLOAK_SERVER_URL + "/realms/" + REALM + "/protocol/openid-connect/logout";

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", CLIENT_ID);
            body.add("client_secret", CLIENT_SECRET);
            body.add("refresh_token", refreshToken); // Use refresh token to log out

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            restTemplate.postForEntity(logoutUrl, request, String.class);

            return ResponseEntity.ok("User logged out successfully.");
        } catch (HttpClientErrorException e) {
            return ResponseEntity
                    .status(e.getStatusCode())
                    .body("Logout failed: " + e.getResponseBodyAsString());
        }
    }


    private String getKeycloakUserId(String email, String adminToken) {
        String getUsersUrl = KEYCLOAK_SERVER_URL + "/admin/realms/" + REALM + "/users?email=" + email;

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);
        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<String> response = restTemplate.exchange(
                getUsersUrl, HttpMethod.GET, request, String.class
        );

        if (response.getStatusCode().is2xxSuccessful()) {
            JSONArray usersArray = new JSONArray(response.getBody());
            if (usersArray.length() > 0) {
                return usersArray.getJSONObject(0).getString("id"); // Extract Keycloak user ID
            }
        }

        return null; // User not found
    }


    private void saveUserToDatabase(String keycloakId, String username, String email, String firstName, String lastName, String roleName) {
        User user = new User();
        user.setKeycloakId(keycloakId);  // Save Keycloak ID
        user.setEmail(email);

        // Assign role
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleName));

        user.setRoles(Set.of(role));

        userRepository.save(user);
    }


    /**
     * Validate user token
     *
     * @param token Access token to validate
     * @return Token validation result
     */
    public ResponseEntity<Map<String, Object>> validateToken(String token) {
        String introspectionUrl = KEYCLOAK_SERVER_URL + "/realms/" + REALM + "/protocol/openid-connect/token/introspect";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", CLIENT_ID);
        body.add("client_secret", CLIENT_SECRET);
        body.add("token", token);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(
                    introspectionUrl,
                    request,
                    Map.class
            );

            return ResponseEntity
                    .status(response.getStatusCode())
                    .body(response.getBody());

        } catch (HttpClientErrorException e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Token validation failed");
            errorResponse.put("status", e.getStatusCode().value());

            return ResponseEntity
                    .status(e.getStatusCode())
                    .body(errorResponse);
        }
    }
}
