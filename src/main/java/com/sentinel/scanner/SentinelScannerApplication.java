package com.sentinel.scanner;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Sentinel Web Application Security Scanner
 * Main Application Entry Point
 * 
 * @author Sentinel Team
 * @version 1.0
 */
@SpringBootApplication
public class SentinelScannerApplication {

    public static void main(String[] args) {
        SpringApplication.run(SentinelScannerApplication.class, args);
        System.out.println("==============================================");
        System.out.println("  SENTINEL SECURITY SCANNER - STARTED");
        System.out.println("  Backend running on: http://localhost:8080");
        System.out.println("  Frontend: Open index.html in browser");
        System.out.println("==============================================");
    }

    /**
     * Configure CORS to allow frontend communication
     */
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("*")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*");
            }
        };
    }
}