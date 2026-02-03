package com.sentinel.scanner.service;

import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * Service for handling authentication with DVWA and Juice Shop
 */
@Service
public class AuthenticationService {

    /**
     * Attempt to login to DVWA
     */
    public Map<String, String> loginToDVWA(String baseUrl) {
        Map<String, String> cookies = new HashMap<>();
        
        try {
            System.out.println("Attempting DVWA login...");
            
            // Step 1: Get initial cookies and CSRF token
            String loginUrl = baseUrl.endsWith("/") ? baseUrl + "login.php" : baseUrl + "/login.php";
            
            Connection.Response initialResponse = Jsoup.connect(loginUrl)
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .timeout(10000)
                .method(Connection.Method.GET)
                .execute();
            
            cookies.putAll(initialResponse.cookies());
            
            // Step 2: Extract CSRF token if present
            Document loginPage = initialResponse.parse();
            String csrfToken = "";
            if (loginPage.select("input[name=user_token]").first() != null) {
                csrfToken = loginPage.select("input[name=user_token]").first().attr("value");
            }
            
            // Step 3: Attempt login with default credentials
            Map<String, String> loginData = new HashMap<>();
            loginData.put("username", "admin");
            loginData.put("password", "password");
            loginData.put("Login", "Login");
            if (!csrfToken.isEmpty()) {
                loginData.put("user_token", csrfToken);
            }
            
            Connection.Response loginResponse = Jsoup.connect(loginUrl)
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .cookies(cookies)
                .data(loginData)
                .timeout(10000)
                .followRedirects(true)
                .method(Connection.Method.POST)
                .execute();
            
            cookies.putAll(loginResponse.cookies());
            
            // Step 4: Set security level to low
            String securityUrl = baseUrl.endsWith("/") ? baseUrl + "security.php" : baseUrl + "/security.php";
            Connection.Response securityResponse = Jsoup.connect(securityUrl)
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .cookies(cookies)
                .data("security", "low")
                .data("seclev_submit", "Submit")
                .timeout(10000)
                .followRedirects(true)
                .method(Connection.Method.POST)
                .execute();
            
            cookies.putAll(securityResponse.cookies());
            
            System.out.println("✓ DVWA login successful with " + cookies.size() + " cookies");
            
        } catch (Exception e) {
            System.out.println("DVWA login failed: " + e.getMessage());
        }
        
        return cookies;
    }

    /**
     * Attempt to interact with Juice Shop
     */
    public Map<String, String> initializeJuiceShop(String baseUrl) {
        Map<String, String> cookies = new HashMap<>();
        
        try {
            System.out.println("Initializing Juice Shop session...");
            
            // Step 1: Visit main page to get initial cookies
            Connection.Response response = Jsoup.connect(baseUrl)
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .timeout(10000)
                .followRedirects(true)
                .method(Connection.Method.GET)
                .execute();
            
            cookies.putAll(response.cookies());
            
            // Step 2: Try to access REST API endpoints
            String[] apiEndpoints = {
                "/rest/products/search",
                "/rest/user/whoami",
                "/api/Challenges"
            };
            
            for (String endpoint : apiEndpoints) {
                try {
                    String apiUrl = baseUrl.endsWith("/") ? baseUrl + endpoint.substring(1) : baseUrl + endpoint;
                    Connection.Response apiResponse = Jsoup.connect(apiUrl)
                        .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                        .cookies(cookies)
                        .timeout(5000)
                        .ignoreContentType(true)
                        .ignoreHttpErrors(true)
                        .method(Connection.Method.GET)
                        .execute();
                    
                    cookies.putAll(apiResponse.cookies());
                } catch (Exception e) {
                    // Continue with other endpoints
                }
            }
            
            System.out.println("✓ Juice Shop initialized with " + cookies.size() + " cookies");
            
        } catch (Exception e) {
            System.out.println("Juice Shop initialization failed: " + e.getMessage());
        }
        
        return cookies;
    }

    /**
     * Detect application type and login accordingly
     */
    public Map<String, String> autoAuthenticate(String targetUrl) {
        Map<String, String> cookies = new HashMap<>();
        
        try {
            // Visit the target URL
            Connection.Response response = Jsoup.connect(targetUrl)
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .timeout(10000)
                .followRedirects(true)
                .method(Connection.Method.GET)
                .execute();
            
            String body = response.body().toLowerCase();
            cookies.putAll(response.cookies());
            
            // Detect DVWA
            if (body.contains("damn vulnerable web") || body.contains("dvwa") || targetUrl.toLowerCase().contains("dvwa")) {
                System.out.println("Detected DVWA application");
                cookies.putAll(loginToDVWA(extractBaseUrl(targetUrl)));
            }
            // Detect Juice Shop
            else if (body.contains("juice shop") || body.contains("owasp") || targetUrl.toLowerCase().contains("juice")) {
                System.out.println("Detected Juice Shop application");
                cookies.putAll(initializeJuiceShop(extractBaseUrl(targetUrl)));
            }
            // Generic session initialization
            else {
                System.out.println("Generic application - using default session");
            }
            
        } catch (Exception e) {
            System.out.println("Auto-authentication failed: " + e.getMessage());
        }
        
        return cookies;
    }

    /**
     * Extract base URL from full URL
     */
    private String extractBaseUrl(String url) {
        try {
            if (url.contains("://")) {
                String[] parts = url.split("://");
                String protocol = parts[0];
                String rest = parts[1];
                String host = rest.split("/")[0];
                return protocol + "://" + host;
            }
        } catch (Exception e) {
            // Return as is
        }
        return url;
    }
}