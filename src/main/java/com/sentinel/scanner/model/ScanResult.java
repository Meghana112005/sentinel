package com.sentinel.scanner.model;

import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * Entity class representing a vulnerability scan result
 * Stored in MySQL database
 */
@Entity
@Table(name = "scan_results")
public class ScanResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String targetUrl;

    @Column(nullable = false)
    private String vulnerabilityType; // SQL_INJECTION, XSS, etc.

    @Column(length = 2000)
    private String affectedUrl;

    @Column(length = 1000)
    private String payload;

    @Column(length = 5000)
    private String evidence;

    @Column(nullable = false)
    private String riskLevel; // HIGH, MEDIUM, LOW

    @Column(nullable = false)
    private LocalDateTime scanDate;

    @Column(length = 50)
    private String scanId; // Unique identifier for each scan session

    // Constructors
    public ScanResult() {
        this.scanDate = LocalDateTime.now();
    }

    public ScanResult(String targetUrl, String vulnerabilityType, String affectedUrl, 
                     String payload, String evidence, String riskLevel, String scanId) {
        this.targetUrl = targetUrl;
        this.vulnerabilityType = vulnerabilityType;
        this.affectedUrl = affectedUrl;
        this.payload = payload;
        this.evidence = evidence;
        this.riskLevel = riskLevel;
        this.scanId = scanId;
        this.scanDate = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getTargetUrl() { return targetUrl; }
    public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }

    public String getVulnerabilityType() { return vulnerabilityType; }
    public void setVulnerabilityType(String vulnerabilityType) { 
        this.vulnerabilityType = vulnerabilityType; 
    }

    public String getAffectedUrl() { return affectedUrl; }
    public void setAffectedUrl(String affectedUrl) { this.affectedUrl = affectedUrl; }

    public String getPayload() { return payload; }
    public void setPayload(String payload) { this.payload = payload; }

    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public LocalDateTime getScanDate() { return scanDate; }
    public void setScanDate(LocalDateTime scanDate) { this.scanDate = scanDate; }

    public String getScanId() { return scanId; }
    public void setScanId(String scanId) { this.scanId = scanId; }
}