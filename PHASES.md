# TLS Monitor - Phase-by-Phase Development Checklist

This checklist tracks the implementation progress of the **Fresh TLS Certificate Monitoring and Web Security Analysis Tool** according to the project specification.

---

## Progress Overview

| Phase | Description | Status | Deliverable Gate |
|---|---|---|---|
| **Phase 0** | Requirement Confirmation & Planning | 🔄 In Progress | Requirements, safe scan policy, and repo baseline documented |
| **Phase 1** | Verified Development Environment | 🔄 In Progress | JDK 21/25, Maven, PostgreSQL, and Git verified |
| **Phase 2** | Spring Boot + Vaadin Runnable Baseline | ⏳ Pending | Clean project compiles, starts, and displays Vaadin UI |
| **Phase 3** | Database Connectivity & Persistence | ⏳ Pending | PostgreSQL connection and JPA test pass |
| **Phase 4** | Package Structure, Common Models & Error Handling | ⏳ Pending | Clean architecture, DTOs, domain models, and error handling |
| **Phase 5** | Authentication & Dashboard Shell | ⏳ Pending | Admin registration, BCrypt authentication, protected routes |
| **Phase 6** | Module 1: Website Inventory | ⏳ Pending | Domain/URL CRUD, validation, and anti-SSRF protections |
| **Phase 7** | Module 2: TLS Certificate Inspection Engine | ⏳ Pending | JSSE TLS sockets, X.509 parsing, protocol & cipher probe |
| **Phase 8** | Module 3: Expiry & Risk Scoring Engine | ⏳ Pending | Rules engine, expiry calculation, transparent scoring |
| **Phase 9** | Module 4: Reporting & Alert Generation | ⏳ Pending | PDF (OpenPDF), Excel (Apache POI), Email & Scheduler |
| **Phase 10**| Integrated Workflow & End-to-End Testing | ⏳ Pending | Full user flow: Add -> Scan -> Score -> Alert -> Report |
| **Phase 11**| Security Review & Hardening | ⏳ Pending | SSRF tests, DNS rebinding, timeout & input sanitization |
| **Phase 12**| Deployment, Handover & Documentation | ⏳ Pending | Production config, migrations, user guide, final verification |

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
- [ ] PostgreSQL 17 downloaded, initialized, and verified running on port 5432.
- [ ] Create database `tls_monitoring_db`.

### Phase 2: Application Skeleton & Runnable Baseline
- [ ] Generate Spring Boot 3.4 / Vaadin 24.x application with Maven wrapper (`pom.xml`).
- [ ] Add dependencies: Spring Web, Spring Security, Spring Data JPA, Vaadin, OpenPDF, Apache POI, Jakarta Validation, PostgreSQL Driver.
- [ ] Verify clean compilation (`mvn clean compile`).
- [ ] Verify baseline launch and initial Vaadin view.

### Phase 3: Database Connectivity & JPA Persistence
- [ ] Configure `application.properties` with environment variables for database credentials.
- [ ] Implement JPA repository and verify entity persistence with integration test.
- [ ] Confirm table generation in PostgreSQL `tls_monitoring_db`.

### Phase 4: Core Architecture & Error Handling
- [ ] Establish package structure: `config`, `authentication`, `dashboard`, `inventory`, `inspection`, `risk`, `reporting`, `alerts`, `common`.
- [ ] Implement Global Exception Handler, API response wrappers, and security boundary DTOs.

### Phase 5: Authentication & Dashboard Shell
- [ ] Implement `User` entity, `UserRepository`, and `UserService` with BCrypt password hashing.
- [ ] Setup first-time admin setup flow.
- [ ] Build Vaadin `LoginView` and `MainLayout` with responsive navigation sidebar.
- [ ] Build `DashboardView` with statistical cards and summary tables.

### Phase 6: Module 1 - Website Inventory
- [ ] Create `Website` entity and `WebsiteRepository`.
- [ ] Implement `WebsiteValidationService` with SSRF blocking (disallowing private IPs, loopback, link-local, cloud metadata).
- [ ] Implement `WebsiteService` for CRUD operations.
- [ ] Build `WebsiteView` in Vaadin (Add, Edit, Delete, Search, and Scan trigger).

### Phase 7: Module 2 - TLS Certificate & Configuration Inspection
- [ ] Build `TLSInspector` using Java JSSE (`SSLSocketFactory`, `SSLSocket`, `SSLParameters`).
- [ ] Implement certificate parsing (`X509Certificate` subject, issuer, serial, dates, SANs, SHA-256 fingerprint).
- [ ] Implement trust validation and HTTPS hostname verification.
- [ ] Build `TLSConfigurationScanner` for individual protocol capability tests (TLS 1.0, 1.1, 1.2, 1.3) and cipher suite recording.
- [ ] Persist `TLSScanResult` and `CertificateDetails`.
- [ ] Build `TLSInspectionView` in Vaadin with detailed certificate inspect dialog.

### Phase 8: Module 3 - Certificate Expiry & Risk Detection
- [ ] Implement `ExpiryChecker` with UTC-based date calculation and category thresholds.
- [ ] Implement extensible `RiskRule` interface and concrete rule implementations.
- [ ] Implement `RiskScoringService` (0-100 score, severity mapping: Low, Medium, High, Critical).
- [ ] Persist `SecurityFinding` and `RiskAssessment`.
- [ ] Build `RiskAnalysisView` with vulnerability breakdown and remediation guidance.

### Phase 9: Module 4 - Reporting & Alert Generation
- [ ] Implement `PdfReportService` using OpenPDF for comprehensive audit reports.
- [ ] Implement `ExcelReportService` using Apache POI for multi-sheet workbooks.
- [ ] Implement `EmailService` and `AlertService` with deduplication and acknowledgement.
- [ ] Implement `MonitoringScheduler` for automated recurring scans with bounded executor.
- [ ] Build `ReportsView` and `AlertsView` in Vaadin.

### Phase 10: System Integration & Workflow Verification
- [ ] Connect inventory "Scan Now" button with asynchronous scan pipeline.
- [ ] Verify automatic chain: Scan -> Certificate Parsing -> Risk Assessment -> Alert Generation -> Dashboard Update.
- [ ] Verify manual export of PDF and Excel reports.

### Phase 11: Security Review & Hardening
- [ ] Audit anti-SSRF protections against IPv4/IPv6 private ranges and DNS rebinding.
- [ ] Verify rate limiting and timeout configurations.
- [ ] Verify input sanitization and secure error handling.

### Phase 12: Deployment & Final Handover
- [ ] Setup production profile and environment variable guidelines.
- [ ] Verify Maven production build (`mvn clean package`).
- [ ] Create comprehensive `README.md`, architecture docs, and database schema documentation.
