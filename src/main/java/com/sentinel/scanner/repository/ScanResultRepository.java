package com.sentinel.scanner.repository;

import com.sentinel.scanner.model.ScanResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

/**
 * Repository interface for ScanResult entity
 * Provides database operations using Spring Data JPA
 */
@Repository
public interface ScanResultRepository extends JpaRepository<ScanResult, Long> {
    
    /**
     * Find all scan results by scan ID
     * @param scanId Unique identifier for scan session
     * @return List of scan results
     */
    List<ScanResult> findByScanId(String scanId);
    
    /**
     * Find all scan results by target URL
     * @param targetUrl The scanned website URL
     * @return List of scan results
     */
    List<ScanResult> findByTargetUrl(String targetUrl);
    
    /**
     * Find all scan results by vulnerability type
     * @param vulnerabilityType Type of vulnerability (SQL_INJECTION, XSS)
     * @return List of scan results
     */
    List<ScanResult> findByVulnerabilityType(String vulnerabilityType);
    
    /**
     * Find all scan results by risk level
     * @param riskLevel Risk level (HIGH, MEDIUM, LOW)
     * @return List of scan results
     */
    List<ScanResult> findByRiskLevel(String riskLevel);
}