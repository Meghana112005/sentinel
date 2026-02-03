package com.sentinel.scanner.service;

import com.sentinel.scanner.model.ScanResult;
import org.springframework.stereotype.Service;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Service for generating security scan reports
 */
@Service
public class ReportService {

    /**
     * Generate HTML report from scan results
     */
    public String generateHtmlReport(List<ScanResult> results, String scanId) {
        if (results.isEmpty()) {
            return generateNoVulnerabilitiesReport(scanId);
        }

        // Group vulnerabilities by type
        Map<String, Long> vulnCounts = results.stream()
            .collect(Collectors.groupingBy(ScanResult::getVulnerabilityType, Collectors.counting()));

        // Group by risk level
        Map<String, Long> riskCounts = results.stream()
            .collect(Collectors.groupingBy(ScanResult::getRiskLevel, Collectors.counting()));

        long highRisk = riskCounts.getOrDefault("HIGH", 0L);
        long mediumRisk = riskCounts.getOrDefault("MEDIUM", 0L);
        long lowRisk = riskCounts.getOrDefault("LOW", 0L);

        String targetUrl = results.isEmpty() ? "Unknown" : results.get(0).getTargetUrl();
        String scanDate = results.isEmpty() ? "" : 
            results.get(0).getScanDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n");
        html.append("<html lang='en'>\n<head>\n");
        html.append("<meta charset='UTF-8'>\n");
        html.append("<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n");
        html.append("<title>Sentinel Security Report - ").append(scanId).append("</title>\n");
        html.append("<style>\n");
        html.append("* { margin: 0; padding: 0; box-sizing: border-box; }\n");
        html.append("body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }\n");
        html.append(".container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden; }\n");
        html.append(".header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; }\n");
        html.append(".header h1 { font-size: 32px; margin-bottom: 10px; }\n");
        html.append(".header p { font-size: 16px; opacity: 0.9; }\n");
        html.append(".summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; }\n");
        html.append(".stat-box { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #667eea; }\n");
        html.append(".stat-box.high { border-left-color: #e74c3c; }\n");
        html.append(".stat-box.medium { border-left-color: #f39c12; }\n");
        html.append(".stat-box.low { border-left-color: #3498db; }\n");
        html.append(".stat-box h3 { font-size: 36px; color: #333; margin-bottom: 5px; }\n");
        html.append(".stat-box p { color: #666; font-size: 14px; }\n");
        html.append(".content { padding: 30px; }\n");
        html.append(".vuln-card { background: white; border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; margin-bottom: 20px; }\n");
        html.append(".vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }\n");
        html.append(".vuln-type { font-size: 20px; font-weight: bold; color: #333; }\n");
        html.append(".risk-badge { padding: 6px 16px; border-radius: 20px; font-size: 12px; font-weight: bold; }\n");
        html.append(".risk-high { background: #ffe0e0; color: #c0392b; }\n");
        html.append(".risk-medium { background: #fff4e0; color: #d68910; }\n");
        html.append(".risk-low { background: #e0f0ff; color: #2471a3; }\n");
        html.append(".detail-row { margin: 10px 0; font-size: 14px; }\n");
        html.append(".detail-label { font-weight: bold; color: #555; display: inline-block; width: 150px; }\n");
        html.append(".detail-value { color: #333; word-break: break-all; }\n");
        html.append(".code-block { background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; font-size: 13px; margin-top: 10px; overflow-x: auto; }\n");
        html.append(".footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; border-top: 1px solid #e0e0e0; }\n");
        html.append("@media print { body { background: white; } .container { box-shadow: none; } }\n");
        html.append("</style>\n</head>\n<body>\n");

        html.append("<div class='container'>\n");
        
        // Header
        html.append("<div class='header'>\n");
        html.append("<h1>🛡️ SENTINEL SECURITY SCAN REPORT</h1>\n");
        html.append("<p>Security Vulnerability Assessment</p>\n");
        html.append("</div>\n");

        // Summary
        html.append("<div class='summary'>\n");
        html.append("<div class='stat-box'>\n");
        html.append("<h3>").append(results.size()).append("</h3>\n");
        html.append("<p>Total Vulnerabilities</p>\n");
        html.append("</div>\n");
        
        html.append("<div class='stat-box high'>\n");
        html.append("<h3>").append(highRisk).append("</h3>\n");
        html.append("<p>High Risk</p>\n");
        html.append("</div>\n");
        
        html.append("<div class='stat-box medium'>\n");
        html.append("<h3>").append(mediumRisk).append("</h3>\n");
        html.append("<p>Medium Risk</p>\n");
        html.append("</div>\n");
        
        html.append("<div class='stat-box low'>\n");
        html.append("<h3>").append(lowRisk).append("</h3>\n");
        html.append("<p>Low Risk</p>\n");
        html.append("</div>\n");
        html.append("</div>\n");

        // Scan Information
        html.append("<div class='content'>\n");
        html.append("<h2 style='margin-bottom: 20px; color: #333;'>Scan Information</h2>\n");
        html.append("<div class='detail-row'><span class='detail-label'>Scan ID:</span> <span class='detail-value'>").append(scanId).append("</span></div>\n");
        html.append("<div class='detail-row'><span class='detail-label'>Target URL:</span> <span class='detail-value'>").append(targetUrl).append("</span></div>\n");
        html.append("<div class='detail-row'><span class='detail-label'>Scan Date:</span> <span class='detail-value'>").append(scanDate).append("</span></div>\n");
        html.append("<hr style='margin: 30px 0; border: none; border-top: 2px solid #e0e0e0;'>\n");

        // Vulnerabilities
        html.append("<h2 style='margin-bottom: 20px; color: #333;'>Detected Vulnerabilities</h2>\n");

        for (ScanResult result : results) {
            html.append("<div class='vuln-card'>\n");
            html.append("<div class='vuln-header'>\n");
            html.append("<div class='vuln-type'>").append(formatVulnType(result.getVulnerabilityType())).append("</div>\n");
            html.append("<div class='risk-badge risk-").append(result.getRiskLevel().toLowerCase()).append("'>")
                .append(result.getRiskLevel()).append(" RISK</div>\n");
            html.append("</div>\n");
            
            html.append("<div class='detail-row'><span class='detail-label'>Affected URL:</span> <span class='detail-value'>")
                .append(result.getAffectedUrl()).append("</span></div>\n");
            
            html.append("<div class='detail-row'><span class='detail-label'>Payload Used:</span></div>\n");
            html.append("<div class='code-block'>").append(escapeHtml(result.getPayload())).append("</div>\n");
            
            html.append("<div class='detail-row'><span class='detail-label'>Evidence:</span></div>\n");
            html.append("<div class='code-block'>").append(escapeHtml(result.getEvidence())).append("</div>\n");
            
            html.append("</div>\n");
        }

        html.append("</div>\n");

        // Footer
        html.append("<div class='footer'>\n");
        html.append("<p><strong>⚠️ DISCLAIMER:</strong> This tool is for educational and authorized security testing only.</p>\n");
        html.append("<p>Generated by Sentinel Security Scanner v1.0 | © 2025</p>\n");
        html.append("</div>\n");

        html.append("</div>\n");
        html.append("</body>\n</html>");

        return html.toString();
    }

    private String generateNoVulnerabilitiesReport(String scanId) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n<html>\n<head>\n");
        html.append("<title>Sentinel Report - No Vulnerabilities</title>\n");
        html.append("<style>body{font-family:Arial;text-align:center;padding:50px;}</style>\n");
        html.append("</head>\n<body>\n");
        html.append("<h1>✅ No Vulnerabilities Found</h1>\n");
        html.append("<p>Scan ID: ").append(scanId).append("</p>\n");
        html.append("</body>\n</html>");
        return html.toString();
    }

    private String formatVulnType(String type) {
        return type.replace("_", " ");
    }

    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
}