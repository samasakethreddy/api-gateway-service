package com.saketh.pg_api_gateway.services;

import com.saketh.pg_api_gateway.entity.Role;
import com.saketh.pg_api_gateway.entity.User;
import com.saketh.pg_api_gateway.repository.RoleRepository;
import com.saketh.pg_api_gateway.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.json.JSONArray;

@Service
public class KeycloakAdminService {

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

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
     * Create a new user in Keycloak
     *
     * @param username  User's username
     * @param email     User's email
     * @param password  User's password
     * @param firstName
     * @param lastName
     * @param role
     * @return Created user details
     */
    public ResponseEntity<String> createUser(
            String username, String email, String password,
            String firstName, String lastName, String role
    ) {
        String adminToken = getAdminAccessToken();
        String createUserUrl = KEYCLOAK_SERVER_URL + "/admin/realms/" + REALM + "/users";

        try {
            // Prepare user creation payload
            Map<String, Object> userRepresentation = new HashMap<>();
            userRepresentation.put("username", username);
            userRepresentation.put("email", email);
            userRepresentation.put("enabled", true);
            userRepresentation.put("firstName", firstName);
            userRepresentation.put("lastName", lastName);

            // Prepare user credentials
            Map<String, Object> credentialRepresentation = new HashMap<>();
            credentialRepresentation.put("type", "password");
            credentialRepresentation.put("value", password);
            credentialRepresentation.put("temporary", false);

            userRepresentation.put("credentials", List.of(credentialRepresentation));

            // Prepare HTTP request
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(adminToken);

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(userRepresentation, headers);

            // Send user creation request
            ResponseEntity<String> response = restTemplate.exchange(
                    createUserUrl,
                    HttpMethod.POST,
                    request,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                // Retrieve the user ID from Keycloak
                String userId = getKeycloakUserId(email, adminToken);

                if (userId == null) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to retrieve Keycloak user ID.");
                }

                // Save user details in the database
                saveUserToDatabase(userId, username, email, firstName, lastName, role);

                return ResponseEntity.ok("User created successfully.");
            }

            return ResponseEntity.status(response.getStatusCode()).body("User creation failed.");
        } catch (HttpClientErrorException e) {
            return ResponseEntity
                    .status(e.getStatusCode())
                    .body("User creation failed: " + e.getResponseBodyAsString());
        }
    }


    /**
     * Authenticate user and obtain access token
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
