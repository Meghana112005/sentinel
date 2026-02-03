package com.sentinel.scanner.controller;

import com.sentinel.scanner.model.ScanResult;
import com.sentinel.scanner.service.ReportService;
import com.sentinel.scanner.service.ScannerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * REST API Controller for Sentinel Scanner
 * Exposes endpoints for scanning and retrieving results
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ScannerController {

    @Autowired
    private ScannerService scannerService;
    @Autowired
    private ReportService reportService;

    /**
     * Health check endpoint
     * GET /api/health
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> healthCheck() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "Sentinel Security Scanner");
        response.put("version", "1.0");
        return ResponseEntity.ok(response);
    }

    /**
     * Start a new security scan
     * POST /api/scan
     * Request Body: { "targetUrl": "http://example.com" }
     */
    @PostMapping("/scan")
    public ResponseEntity<Map<String, Object>> startScan(@RequestBody Map<String, String> request) {
        try {
            String targetUrl = request.get("targetUrl");
            
            // Validate URL
            if (targetUrl == null || targetUrl.trim().isEmpty()) {
                Map<String, Object> error = new HashMap<>();
                error.put("status", "error");
                error.put("message", "Target URL is required");
                return ResponseEntity.badRequest().body(error);
            }

            // Normalize URL
            if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
                targetUrl = "http://" + targetUrl;
            }

            // Perform scan
            Map<String, Object> result = scannerService.performScan(targetUrl);
            
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    /**
     * Get scan results by scan ID
     * GET /api/results/{scanId}
     */
    @GetMapping("/results/{scanId}")
    public ResponseEntity<Map<String, Object>> getResults(@PathVariable String scanId) {
        try {
            List<ScanResult> results = scannerService.getResultsByScanId(scanId);
            
            Map<String, Object> response = new HashMap<>();
            response.put("scanId", scanId);
            response.put("vulnerabilitiesFound", results.size());
            response.put("vulnerabilities", results);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    /**
     * Generate HTML report for a scan
     * GET /api/report/{scanId}
     */
    @GetMapping("/report/{scanId}")
    public ResponseEntity<Map<String, String>> generateReport(@PathVariable String scanId) {
        try {
            List<ScanResult> results = scannerService.getResultsByScanId(scanId);
            String reportHtml = reportService.generateHtmlReport(results, scanId);
            
            Map<String, String> response = new HashMap<>();
            response.put("scanId", scanId);
            response.put("report", reportHtml);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    /**
     * Get scanning statistics
     * GET /api/stats
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStatistics() {
        // This can be expanded to show database statistics
        Map<String, Object> stats = new HashMap<>();
        stats.put("status", "operational");
        stats.put("message", "Scanner ready for operation");
        return ResponseEntity.ok(stats);
    }
}