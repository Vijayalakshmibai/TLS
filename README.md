# Fresh TLS Certificate Monitoring and Web Security Analysis Tool

A professional, full-stack Java platform for cybersecurity and web infrastructure monitoring. This tool inspects SSL/TLS certificates, verifies cryptographic cipher suites and protocols, assesses security configurations, detects certificate expiry risks, tracks historical trends, and generates automated alerts and audit-ready PDF/Excel reports.

---

## 🛠 Technology Stack

- **Runtime & Language**: Java 21 LTS (Temurin OpenJDK)
- **Framework**: Spring Boot 3.4.x / Vaadin Flow 24.x
- **Security & Auth**: Spring Security 6.x (BCrypt, Session Management, RBAC)
- **TLS Inspection Engine**: Native Java JSSE (`SSLSocket`, `SSLContext`, `SSLSession`, `SSLParameters`)
- **Certificate Analysis**: Java Cryptography & X.509 API (`X509Certificate`, `MessageDigest`, `CertificateFactory`)
- **Persistence Layer**: Spring Data JPA, Hibernate, PostgreSQL 17
- **Reporting Engine**: OpenPDF (PDF Generation) & Apache POI (Excel Reports)
- **Scheduling & Notifications**: Spring Scheduler & Spring Boot Mail
- **Build Tool**: Apache Maven 3.9.x / Maven Wrapper

---

## 🏛 System Architecture & Four Core Modules

```
                           +----------------------------------------+
                           |       Vaadin 24.x User Interface       |
                           | (Dashboard, Inventory, Scan, Reports)  |
                           +----------------------------------------+
                                              |
                           +----------------------------------------+
                           |          Spring Boot Backend           |
                           |   (Security, REST Controllers, Service)|
                           +----------------------------------------+
                               /              |               \
                              /               |                \
     +--------------------------+  +--------------------+  +----------------------+
     | Module 1: Inventory      |  | Module 2: TLS      |  | Module 3: Risk Engine|
     | - Endpoint Management    |  | - JSSE SSLSocket   |  | - Expiry Calculation|
     | - SSRF / DNS Validation  |  | - X.509 Parsing    |  | - Security Findings  |
     | - Domain Normalization   |  | - Protocol Probing |  | - Risk Scoring (0-100|
     +--------------------------+  +--------------------+  +----------------------+
                              \               |                /
                               \              |               /
                           +----------------------------------------+
                           |  Module 4: Reporting & Alerts Engine   |
                           |  - OpenPDF Reports                     |
                           |  - Apache POI Excel Workbooks          |
                           |  - Email Alerts & Deduplication        |
                           |  - Automated Spring Scheduler          |
                           +----------------------------------------+
                                              |
                           +----------------------------------------+
                           |         PostgreSQL Database            |
                           |   (Websites, Scans, Certs, Findings)   |
                           +----------------------------------------+
```

---

## 🛡 Security Scanning Boundaries & Safe Scan Policy

To protect internal systems and adhere to cybersecurity best practices:
1. **SSRF Defenses**: Arbitrary internal, private, loopback (`127.0.0.1`, `localhost`), link-local (`169.254.0.0/16`), and cloud metadata (`169.254.169.254`) addresses are strictly blocked during registration and rechecked before connection.
2. **Standardized Port**: Default inspection port is HTTPS 443 with timeout guards (5-second connect timeout, 5-second handshake timeout).
3. **No Insecure Trust Bypass in Production**: Validates certificate trust using the standard Java TrustManager while recording detailed validation failures safely.
4. **Rate Limiting & Bounded Concurrency**: Background inspection tasks execute within a bounded thread pool to avoid overwhelming remote hosts.
