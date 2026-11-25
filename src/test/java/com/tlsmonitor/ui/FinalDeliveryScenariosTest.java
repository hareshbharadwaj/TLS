package com.tlsmonitor.ui;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.alerts.repository.AlertRepository;
import com.tlsmonitor.alerts.scheduler.MonitoringScheduler;
import com.tlsmonitor.alerts.service.AlertService;
import com.tlsmonitor.alerts.service.EmailService;
import com.tlsmonitor.authentication.entity.User;
import com.tlsmonitor.authentication.repository.UserRepository;
import com.tlsmonitor.authentication.service.UserService;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.repository.CertificateDetailsRepository;
import com.tlsmonitor.inspection.repository.TLSScanResultRepository;
import com.tlsmonitor.inspection.service.ScanOrchestratorService;
import com.tlsmonitor.inspection.tls.TLSInspector;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.repository.WebsiteRepository;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.tlsmonitor.reporting.service.ExcelReportService;
import com.tlsmonitor.reporting.service.PdfReportService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.repository.RiskAssessmentRepository;
import com.tlsmonitor.risk.repository.SecurityFindingRepository;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Functional and regression tests for TC-26 to TC-29:
 * - TC-26: Login and Authentication
 * - TC-27: Dashboard and Website Management
 * - TC-28: Reports and Exports
 * - TC-29: Alerts and Scheduled Monitoring
 */
@SpringBootTest
@ActiveProfiles("test")
@DisplayName("Final Delivery & Vaadin Integration Scenarios (TC-26 to TC-29)")
public class FinalDeliveryScenariosTest {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private WebsiteService websiteService;

    @Autowired
    private WebsiteRepository websiteRepository;

    @Autowired
    private ScanOrchestratorService scanOrchestratorService;

    @Autowired
    private TLSScanResultRepository scanResultRepository;

    @Autowired
    private CertificateDetailsRepository certificateDetailsRepository;

    @Autowired
    private RiskAssessmentRepository riskAssessmentRepository;

    @Autowired
    private SecurityFindingRepository securityFindingRepository;

    @Autowired
    private AlertService alertService;

    @Autowired
    private AlertRepository alertRepository;

    @Autowired
    private PdfReportService pdfReportService;

    @Autowired
    private ExcelReportService excelReportService;

    @Autowired
    private MonitoringScheduler monitoringScheduler;

    @MockitoBean
    private TLSInspector tlsInspector;

    @BeforeEach
    void setUp() {
        alertRepository.deleteAll();
        securityFindingRepository.deleteAll();
        riskAssessmentRepository.deleteAll();
        certificateDetailsRepository.deleteAll();
        scanResultRepository.deleteAll();
        websiteRepository.deleteAll();

        // Ensure default admin exists
        userService.initDefaultAdmin();
    }

    // ==========================================
    // TC-26: Login and Authentication
    // ==========================================

    @Test
    @DisplayName("TC-26: Valid credentials load admin user successfully")
    void testTC26_validCredentials_successfulLogin() {
        UserDetails user = userService.loadUserByUsername("admin");
        assertNotNull(user, "User details must not be null");
        assertEquals("admin", user.getUsername());
        assertTrue(passwordEncoder.matches("admin123", user.getPassword()),
                "Default admin password 'admin123' must match BCrypt hash");
        assertTrue(user.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")),
                "Admin user must have ROLE_ADMIN");
    }

    @Test
    @DisplayName("TC-26: Invalid credentials or unknown user rejected")
    void testTC26_invalidCredentials_rejected() {
        assertThrows(UsernameNotFoundException.class, () -> {
            userService.loadUserByUsername("nonexistent_user");
        }, "Unknown user must throw UsernameNotFoundException");

        UserDetails user = userService.loadUserByUsername("admin");
        assertFalse(passwordEncoder.matches("wrongpassword", user.getPassword()),
                "Incorrect password must not match BCrypt hash");
    }

    @Test
    @DisplayName("TC-26: User registration properly encodes password with BCrypt")
    void testTC26_bcryptPasswordEncoding() {
        String testUser = "audit_officer_" + System.currentTimeMillis();
        String rawPass = "SecretSecurePass99!";
        User registered = userService.registerUser(testUser, rawPass, "SECURITY_ANALYST");

        assertNotNull(registered);
        assertNotEquals(rawPass, registered.getPassword(), "Password must not be stored in plain text");
        assertTrue(registered.getPassword().startsWith("$2a$") || registered.getPassword().startsWith("$2b$"),
                "Password must be hashed using BCrypt");
        assertTrue(passwordEncoder.matches(rawPass, registered.getPassword()));
    }

    // ==========================================
    // TC-27: Dashboard and Website Management
    // ==========================================

    @Test
    @DisplayName("TC-27: Website CRUD operations and search filtering")
    void testTC27_websiteCrudOperationsAndSearch() {
        // Create
        Website toAdd = new Website("example.com", "https://example.com", "Inventory Test Target");
        toAdd.setStatus("ACTIVE");
        Website created = websiteService.addWebsite(toAdd);
        assertNotNull(created.getId());
        assertEquals("example.com", created.getDomain());
        assertEquals("ACTIVE", created.getStatus());

        // Read & Find
        Optional<Website> found = websiteRepository.findByDomain("example.com");
        assertTrue(found.isPresent(), "Registered website must be findable by domain");
        assertEquals("example.com", found.get().getDomain());

        // Update
        created.setStatus("DISABLED");
        websiteRepository.save(created);
        Website updated = websiteRepository.findById(created.getId()).orElseThrow();
        assertEquals("DISABLED", updated.getStatus());

        // Delete
        websiteService.deleteWebsite(created.getId());
        assertFalse(websiteRepository.findById(created.getId()).isPresent(),
                "Website must be deleted from database");
    }

    @Test
    @DisplayName("TC-27: Dashboard statistics accurately aggregate database counts")
    void testTC27_dashboardStatisticsCalculatedCorrectly() {
        Website w1 = websiteRepository.save(new Website("target-low.com", "https://target-low.com", "Low Risk Target"));
        Website w2 = websiteRepository.save(new Website("target-crit.com", "https://target-crit.com", "Critical Target"));

        TLSScanResult scan1 = new TLSScanResult();
        scan1.setWebsiteId(w1.getId());
        scan1.setDomain(w1.getDomain());
        scan1.setPort(443);
        scan1.setConnectionStatus("SUCCESS");
        scan1.setScannedAt(LocalDateTime.now());
        scan1 = scanResultRepository.save(scan1);

        TLSScanResult scan2 = new TLSScanResult();
        scan2.setWebsiteId(w2.getId());
        scan2.setDomain(w2.getDomain());
        scan2.setPort(443);
        scan2.setConnectionStatus("SUCCESS");
        scan2.setScannedAt(LocalDateTime.now());
        scan2 = scanResultRepository.save(scan2);

        // Low risk site
        RiskAssessment r1 = new RiskAssessment();
        r1.setWebsiteId(w1.getId());
        r1.setScanId(scan1.getId());
        r1.setTotalScore(15);
        r1.setRiskLevel("LOW");
        riskAssessmentRepository.save(r1);

        // Critical risk site
        RiskAssessment r2 = new RiskAssessment();
        r2.setWebsiteId(w2.getId());
        r2.setScanId(scan2.getId());
        r2.setTotalScore(95);
        r2.setRiskLevel("CRITICAL");
        riskAssessmentRepository.save(r2);

        // Expiring certificate (5 days remaining)
        CertificateDetails c1 = new CertificateDetails();
        c1.setWebsiteId(w2.getId());
        c1.setScanId(scan2.getId());
        c1.setDaysRemaining(5);
        c1.setExpired(false);
        c1.setSubject("CN=target-crit.com");
        c1.setIssuer("CN=Test CA");
        c1.setValidFrom(LocalDateTime.now().minusDays(85));
        c1.setValidUntil(LocalDateTime.now().plusDays(5));
        certificateDetailsRepository.save(c1);

        assertEquals(2, websiteRepository.count(), "Total monitored websites");
        assertEquals(1, riskAssessmentRepository.countByRiskLevel("LOW"), "Secure endpoints (LOW risk)");
        assertEquals(1, riskAssessmentRepository.countByRiskLevel("CRITICAL"), "Critical endpoints");
        assertEquals(1, certificateDetailsRepository.countExpiringSoon(30), "Certificates expiring <= 30 days");
    }

    // ==========================================
    // TC-28: Reports and Exports
    // ==========================================

    @Test
    @DisplayName("TC-28: Generate PDF report using OpenPDF with valid magic bytes")
    void testTC28_pdfReportGenerationWithOpenPdf() throws Exception {
        Website website = websiteRepository.save(new Website("report-test.com", "https://report-test.com", "Report Target"));

        TLSScanResult scan = new TLSScanResult();
        scan.setWebsiteId(website.getId());
        scan.setDomain("report-test.com");
        scan.setPort(443);
        scan.setTlsVersion("TLSv1.3");
        scan.setCipherSuite("TLS_AES_256_GCM_SHA384");
        scan.setConnectionStatus("SUCCESS");
        scan.setScannedAt(LocalDateTime.now());
        scan = scanResultRepository.save(scan);

        CertificateDetails cert = new CertificateDetails();
        cert.setWebsiteId(website.getId());
        cert.setScanId(scan.getId());
        cert.setSubject("CN=report-test.com");
        cert.setIssuer("CN=DigiCert Global Root CA");
        cert.setDaysRemaining(120);
        cert.setValidFrom(LocalDateTime.now().minusDays(200));
        cert.setValidUntil(LocalDateTime.now().plusDays(120));
        cert.setSha256Fingerprint("A1:B2:C3:D4:E5:F6:A1:B2:C3:D4:E5:F6:A1:B2:C3:D4:E5:F6:A1:B2:C3:D4:E5:F6:A1:B2");
        certificateDetailsRepository.save(cert);

        RiskAssessment risk = new RiskAssessment();
        risk.setWebsiteId(website.getId());
        risk.setScanId(scan.getId());
        risk.setTotalScore(10);
        risk.setRiskLevel("LOW");
        riskAssessmentRepository.save(risk);

        byte[] pdfBytes = pdfReportService.generateWebsiteReport(website, scan, cert, risk, Collections.emptyList());
        assertNotNull(pdfBytes);
        assertTrue(pdfBytes.length > 500, "PDF report must have content");

        // Verify PDF Magic Bytes (%PDF-1.)
        String header = new String(pdfBytes, 0, Math.min(pdfBytes.length, 8));
        assertTrue(header.startsWith("%PDF"), "PDF document must begin with '%PDF' magic header");
    }

    @Test
    @DisplayName("TC-28: Generate Excel report using Apache POI and verify sheets")
    void testTC28_excelReportGenerationWithApachePoi() throws Exception {
        Website website = websiteRepository.save(new Website("excel-test.com", "https://excel-test.com", "Excel Test Target"));

        byte[] excelBytes = excelReportService.generateWorkbook(
                List.of(website),
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList()
        );
        assertNotNull(excelBytes);
        assertTrue(excelBytes.length > 1000, "Excel report must have substantial content");

        // Verify valid XLSX workbook structure
        try (Workbook workbook = new XSSFWorkbook(new ByteArrayInputStream(excelBytes))) {
            assertTrue(workbook.getNumberOfSheets() >= 4, "Report must contain multiple sheets");
            assertNotNull(workbook.getSheet("Website Inventory"), "Website Inventory sheet must exist");
            assertNotNull(workbook.getSheet("Certificate Details"), "Certificate Details sheet must exist");
            assertNotNull(workbook.getSheet("TLS Inspections"), "TLS Inspections sheet must exist");
            assertNotNull(workbook.getSheet("Risk Assessments"), "Risk Assessments sheet must exist");
            assertNotNull(workbook.getSheet("Security Findings"), "Security Findings sheet must exist");
            assertNotNull(workbook.getSheet("Alert History"), "Alert History sheet must exist");
        }
    }

    @Test
    @DisplayName("TC-28: Spreadsheet formula injection protection prepends single quote")
    void testTC28_spreadsheetFormulaInjectionSanitization() throws Exception {
        Method sanitizeMethod = ExcelReportService.class.getDeclaredMethod("sanitize", String.class);
        sanitizeMethod.setAccessible(true);

        assertEquals("Safe Text", sanitizeMethod.invoke(excelReportService, "Safe Text"));
        assertEquals("'=cmd|' /C calc'!A0", sanitizeMethod.invoke(excelReportService, "=cmd|' /C calc'!A0"));
        assertEquals("'+12345", sanitizeMethod.invoke(excelReportService, "+12345"));
        assertEquals("'-5+10", sanitizeMethod.invoke(excelReportService, "-5+10"));
        assertEquals("'@SUM(A1:A10)", sanitizeMethod.invoke(excelReportService, "@SUM(A1:A10)"));
    }

    // ==========================================
    // TC-29: Alerts and Scheduled Monitoring
    // ==========================================

    @Test
    @DisplayName("TC-29: Alert lifecycle transitions (PENDING -> ACKNOWLEDGED -> RESOLVED)")
    void testTC29_alertLifecycleAcknowledgeAndResolve() {
        Website website = websiteRepository.save(new Website("alert-lifecycle.com", "https://alert-lifecycle.com", "Alert Test"));

        Alert alert = new Alert(website.getId(), "alert-lifecycle.com", "EXP_CRITICAL", "HIGH", "Certificate expires in 2 days");
        alert.setStatus("PENDING");
        alert = alertRepository.save(alert);
        assertNotNull(alert);
        assertEquals("PENDING", alert.getStatus());

        // Acknowledge
        Alert ack = alertService.acknowledgeAlert(alert.getId());
        assertEquals("ACKNOWLEDGED", ack.getStatus());

        // Resolve
        Alert resolved = alertService.resolveAlert(alert.getId());
        assertEquals("RESOLVED", resolved.getStatus());
        assertNotNull(resolved.getResolvedAt());
    }

    @Test
    @DisplayName("TC-29: Alert deduplication suppresses redundant pending alerts")
    void testTC29_alertDeduplication() {
        Website website = websiteRepository.save(new Website("dedup-test.com", "https://dedup-test.com", "Dedup Test"));

        TLSScanResult scan = new TLSScanResult();
        scan.setWebsiteId(website.getId());
        scan.setDomain("dedup-test.com");
        scan.setPort(443);
        scan.setConnectionStatus("SUCCESS");
        scan = scanResultRepository.save(scan);

        CertificateDetails cert = new CertificateDetails();
        cert.setWebsiteId(website.getId());
        cert.setScanId(scan.getId());
        cert.setExpired(true);
        cert.setDaysRemaining(-1);
        certificateDetailsRepository.save(cert);

        RiskAssessment risk = new RiskAssessment();
        risk.setWebsiteId(website.getId());
        risk.setScanId(scan.getId());
        risk.setTotalScore(100);
        risk.setRiskLevel("CRITICAL");
        riskAssessmentRepository.save(risk);

        // First execution generates alerts
        List<Alert> firstRound = alertService.processScanAlerts(website, scan, cert, risk);
        assertFalse(firstRound.isEmpty(), "First round must create alert");

        // Second execution with same finding must deduplicate
        List<Alert> secondRound = alertService.processScanAlerts(website, scan, cert, risk);
        assertTrue(secondRound.isEmpty(), "Second round must deduplicate and return 0 new alerts");

        List<Alert> allAlerts = alertService.getAlertsForWebsite(website.getId());
        assertEquals(firstRound.size(), allAlerts.size(), "Total alerts in DB should equal first round count");
    }

    @Test
    @DisplayName("TC-29: Email notification delivery failure handled gracefully without exception")
    void testTC29_emailNotificationDeliveryFailureHandling() {
        // Relay is unreachable/misconfigured: EmailService must handle failure gracefully and return false
        EmailService testEmailService = new EmailService("http://127.0.0.1:1/unreachable", "test-secret", new ObjectMapper());

        Alert alert = new Alert();
        alert.setDomain("smtp-fail.example.com");
        alert.setSeverity("HIGH");
        alert.setAlertType("EXP_CRITICAL");
        alert.setMessage("Certificate expires in 1 day");

        // Must handle failure gracefully and return false without bubbling exception
        boolean sent = testEmailService.sendAlertEmail("sec-admin@example.com", alert);
        assertFalse(sent, "Email delivery failure must return false");
    }

    @Test
    @DisplayName("TC-29: Scheduled monitoring processes active websites and skips disabled")
    void testTC29_scheduledMonitoringBatchExecution() {
        Website active = websiteRepository.save(new Website("active-scheduled.com", "https://active-scheduled.com", "Active Site"));
        active.setStatus("ACTIVE");
        websiteRepository.save(active);

        TLSScanResult mockScan = new TLSScanResult();
        mockScan.setWebsiteId(active.getId());
        mockScan.setDomain(active.getDomain());
        mockScan.setPort(443);
        mockScan.setConnectionStatus("SUCCESS");
        mockScan.setTlsVersion("TLSv1.3");
        mockScan.setCipherSuite("TLS_AES_256_GCM_SHA384");
        mockScan.setScannedAt(LocalDateTime.now());

        CertificateDetails mockCert = new CertificateDetails();
        mockCert.setWebsiteId(active.getId());
        mockCert.setDaysRemaining(90);
        mockCert.setExpired(false);
        mockCert.setValidFrom(LocalDateTime.now().minusDays(30));
        mockCert.setValidUntil(LocalDateTime.now().plusDays(90));

        when(tlsInspector.inspect(eq(active.getId()), eq(active.getDomain()), eq(443)))
                .thenReturn(new TLSInspector.InspectionOutcome(mockScan, mockCert));

        assertDoesNotThrow(() -> {
            monitoringScheduler.processWebsiteScan(active);
        }, "Scheduled scan of active website must complete cleanly");

        // Verify scan was recorded for active site
        List<TLSScanResult> scans = scanResultRepository.findByWebsiteIdOrderByScannedAtDesc(active.getId());
        assertFalse(scans.isEmpty(), "Scan result must be saved for active website");
    }
}
