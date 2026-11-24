# TLS Monitor - Phase-by-Phase Development Checklist

This checklist tracks the implementation progress of the **Fresh TLS Certificate Monitoring and Web Security Analysis Tool** according to the project specification.

---

## Progress Overview

| Phase | Description | Status | Deliverable Gate |
|---|---|---|---|
| **Phase 0** | Requirement Confirmation & Planning | ✅ Completed | Requirements, safe scan policy, and repo baseline documented |
| **Phase 1** | Verified Development Environment | ✅ Completed | JDK 21/25, Maven, PostgreSQL, and Git verified |
| **Phase 2** | Spring Boot + Vaadin Runnable Baseline | ✅ Completed | Clean project compiles, starts, and displays Vaadin UI |
| **Phase 3** | Database Connectivity & Persistence | ✅ Completed | PostgreSQL connection and JPA test pass |
| **Phase 4** | Package Structure, Common Models & Error Handling | ✅ Completed | Clean architecture, DTOs, domain models, and error handling |
| **Phase 5** | Authentication & Dashboard Shell | ✅ Completed | Admin registration, BCrypt authentication, protected routes |
| **Phase 6** | Module 1: Website Inventory | ✅ Completed | Domain/URL CRUD, validation, and anti-SSRF protections |
| **Phase 7** | Module 2: TLS Certificate Inspection Engine | ✅ Completed | JSSE TLS sockets, X.509 parsing, protocol & cipher probe |
| **Phase 8** | Module 3: Expiry & Risk Scoring Engine | ✅ Completed | Rules engine, expiry calculation, transparent scoring |
| **Phase 9** | Module 4: Reporting & Alert Generation | ✅ Completed | PDF (OpenPDF), Excel (Apache POI), Email & Scheduler |
| **Phase 10**| Integrated Workflow & End-to-End Testing | ✅ Completed | Full user flow: Add -> Scan -> Score -> Alert -> Report |
| **Phase 11**| Security Review & Hardening | ✅ Completed | SSRF tests, DNS rebinding, timeout & input sanitization |
| **Phase 12**| Deployment, Handover & Documentation | ✅ Completed | Production config, standalone JAR, user guide, final verification |

---

## Detailed Task Breakdown

### Phase 0: Requirement Confirmation & Planning
- [x] Inspect workspace and confirm existing files (`TLS Project Requirement.docx` present).
- [x] Read and analyze requirements document completely.
- [x] Document system architecture, safe scanning boundaries, and technical stack.
- [x] Define safe scan constraints (anti-SSRF, timeouts, rate limits, port 443).
- [x] Create project `PHASES.md`, `.gitignore`, and `README.md`.
- [x] Initialize Git repository.

### Phase 1: Environment Setup & Tool Verification
- [x] Java JDK verified (OpenJDK 21.0.12.1 LTS).
- [x] Apache Maven 3.9.9 installed and verified on PATH.
- [x] Git verified (`git version 2.55.0.windows.3`).
- [x] PostgreSQL 17 downloaded, initialized, and verified running on port 5432.
- [x] Create database `tls_monitoring_db`.

### Phase 2: Application Skeleton & Runnable Baseline
- [x] Generate Spring Boot 3.4 / Vaadin 24.x application with Maven wrapper (`pom.xml`).
- [x] Add dependencies: Spring Web, Spring Security, Spring Data JPA, Vaadin, OpenPDF, Apache POI, Jakarta Validation, PostgreSQL Driver.
- [x] Verify clean compilation (`mvn clean compile`).
- [x] Verify baseline launch and initial Vaadin view.

### Phase 3: Database Connectivity & JPA Persistence
- [x] Configure `application.properties` with environment variables for database credentials.
- [x] Implement JPA repository and verify entity persistence with integration test.
- [x] Confirm table generation in PostgreSQL `tls_monitoring_db`.

### Phase 4: Core Architecture & Error Handling
- [x] Establish package structure: `config`, `authentication`, `dashboard`, `inventory`, `inspection`, `risk`, `reporting`, `alerts`, `common`.
- [x] Implement Global Exception Handler, API response wrappers, and security boundary DTOs.
- [x] Configure bounded thread pool executor for background TLS scans.

### Phase 5: Authentication & Dashboard Shell
- [x] Implement `User` entity, `UserRepository`, and `UserService` with BCrypt password hashing.
- [x] Setup first-time admin setup flow.
- [x] Build Vaadin `LoginView` and `MainLayout` with responsive navigation sidebar.
- [x] Build `DashboardView` with statistical cards and summary tables.

### Phase 6: Module 1 - Website Inventory
- [x] Create `Website` entity and `WebsiteRepository`.
- [x] Implement `WebsiteValidationService` with SSRF blocking (disallowing private IPs, loopback, link-local, cloud metadata).
- [x] Implement `WebsiteService` for CRUD operations.
- [x] Build `WebsiteView` in Vaadin (Add, Edit, Delete, Search, and Scan trigger).
- [x] Expose REST endpoints via `WebsiteController`.

### Phase 7: Module 2 - TLS Certificate & Configuration Inspection
- [x] Build `TLSInspector` using Java JSSE (`SSLSocketFactory`, `SSLSocket`, `SSLParameters`).
- [x] Implement certificate parsing (`X509Certificate` subject, issuer, serial, dates, SANs, SHA-256 fingerprint).
- [x] Implement trust validation and HTTPS hostname verification.
- [x] Build `TLSConfigurationScanner` for individual protocol capability tests (TLS 1.0, 1.1, 1.2, 1.3) and cipher suite recording.
- [x] Persist `TLSScanResult` and `CertificateDetails`.
- [x] Build `TLSInspectionView` in Vaadin with detailed certificate inspect dialog.
- [x] Expose REST endpoints via `TLSInspectionController`.

### Phase 8: Module 3 - Certificate Expiry & Risk Detection
- [x] Implement `ExpiryChecker` with UTC-based date calculation and category thresholds.
- [x] Implement extensible `RiskRule` interface and concrete rule implementations.
- [x] Implement `RiskScoringService` (0-100 score, severity mapping: Low, Medium, High, Critical).
- [x] Persist `SecurityFinding` and `RiskAssessment`.
- [x] Build `RiskAnalysisView` with vulnerability breakdown and remediation guidance.
- [x] Expose REST endpoints via `RiskController`.

### Phase 9: Module 4 - Reporting & Alert Generation
- [x] Implement `PdfReportService` using OpenPDF for comprehensive audit reports.
- [x] Implement `ExcelReportService` using Apache POI for multi-sheet workbooks.
- [x] Implement `EmailService` and `AlertService` with deduplication and acknowledgement.
- [x] Implement `MonitoringScheduler` for automated recurring scans with bounded executor.
- [x] Build `ReportsView` and `AlertsView` in Vaadin.

### Phase 10: System Integration & Workflow Verification
- [x] Connect inventory "Scan Now" button with asynchronous scan pipeline.
- [x] Verify automatic chain: Scan -> Certificate Parsing -> Risk Assessment -> Alert Generation -> Dashboard Update.
- [x] Verify manual export of PDF and Excel reports.

### Phase 11: Security Review & Hardening
- [x] Audit anti-SSRF protections against IPv4/IPv6 private ranges and DNS rebinding.
- [x] Verify rate limiting and timeout configurations.
- [x] Verify input sanitization and secure error handling.
- [x] Implement severity floor elevation and calibrate risk rules.

### Phase 12: Deployment & Final Handover
- [x] Setup production profile (`application-prod.properties`) and environment variable guidelines.
- [x] Verify Maven production build (`mvn clean package`) and generate standalone executable JAR.
- [x] Create comprehensive `README.md`, architecture docs, and database schema documentation.

---

## Acceptance Testing Matrix (TC-01 to TC-30)

| Batch | Scope | Test Cases | Status | Automated Test Suite |
| :--- | :--- | :--- | :---: | :--- |
| **Batch 1** | Module 2: Certificate Validation | **TC-01 to TC-05** (Valid HTTPS, Expired, Self-Signed, Host Mismatch, Untrusted Chain) | ✅ PASS | `CertificateValidationScenariosTest` |
| **Batch 2** | Module 3: Expiry Detection & Rules | **TC-06 to TC-10** (Expired, Critical ≤7d, High ≤14d, Medium ≤30d, Low ≤60d, Not Yet Valid) | ✅ PASS | `ExpiryClassificationScenariosTest` |
| **Batch 3** | Module 2: Protocols & Cipher Probing | **TC-11 to TC-15** (TLS 1.0, 1.1, 1.2, 1.3 Detection & Weak Cipher Suite Evaluation) | ✅ PASS | `ProtocolAndCipherScenariosTest` |
| **Batch 4** | Module 1: Validation & Anti-SSRF | **TC-16 to TC-20** (Input Validation, Private/Loopback Blocking, Cloud Metadata, DNS Rebinding, Redirect Safety) | ✅ PASS | `WebsiteValidationAndSsrfScenariosTest` |
| **Batch 5** | Cross-Module: E2E Pipeline | **TC-21 to TC-25** (Inventory to Scan, Scan to Risk, Risk to Alert, DB Persistence, Deduplication & Auto-Resolution) | ✅ PASS | `SystemIntegrationScenariosTest` |
| **Batch 6** | UI & Final Regression | **TC-26 to TC-30** (Login/Auth, Dashboard/Inventory UI, PDF/Excel Exports, Scheduler/Email, Full Regression) | ✅ PASS | `FinalDeliveryScenariosTest` |

