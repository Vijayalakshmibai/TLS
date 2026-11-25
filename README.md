# Fresh TLS Certificate Monitoring and Web Security Analysis Tool

A professional, full-stack Java platform for cybersecurity and web infrastructure monitoring. This tool inspects SSL/TLS certificates, verifies cryptographic cipher suites and protocols, assesses security configurations, detects certificate expiry risks, tracks historical trends, and generates automated alerts and audit-ready PDF/Excel reports.

---

## 🛠 Technology Stack

- **Runtime & Language**: Java 25 LTS (Microsoft OpenJDK)
- **Framework**: Spring Boot 3.4.13 / Vaadin Flow 24.6.5
- **Security & Auth**: Spring Security 6.x (BCrypt password hashing, session protection, route guards)
- **TLS Inspection Engine**: Native Java JSSE (`SSLSocket`, `SSLContext`, `SSLSession`, `SSLParameters`)
- **Certificate Analysis**: Java Cryptography & X.509 API (`X509Certificate`, `MessageDigest`, `CertificateFactory`)
- **Persistence Layer**: Spring Data JPA, Hibernate, PostgreSQL 17
- **Reporting Engine**: OpenPDF (PDF audit reports) & Apache POI (6-sheet Excel workbooks)
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

## 🚀 Quick Start Guide

### 1. Prerequisites
- **Java 25 LTS** or later.
- **PostgreSQL 17** running on `localhost:5432` with database `tls_monitoring_db`.
- The default datasource uses database `tls_monitoring_db`, user `postgres`, and an empty password. Override with `DB_URL`, `DB_USERNAME`, and `DB_PASSWORD` when needed.

### 2. Run a Local Preview (No Login)
This profile disables the login only for a server bound to `127.0.0.1`. Normal runs keep authentication enabled.
```powershell
$env:SPRING_CONFIG_LOCATION = "classpath:/"
$env:SPRING_PROFILES_ACTIVE = "local-preview"
.\mvnw.cmd spring-boot:run
```

### 3. Run with Authentication Enabled
```powershell
Remove-Item Env:SPRING_PROFILES_ACTIVE -ErrorAction SilentlyContinue
.\mvnw.cmd spring-boot:run
```

### 4. Run Built Standalone Production JAR
```powershell
java -jar target/tls-monitor-1.0.0-SNAPSHOT.jar
```

### 5. Build and Run with Docker
Build the production image from the repository root:
```powershell
docker build -t tls-monitor .
```

Run it with a PostgreSQL database reachable from the container. Set `DB_URL`, `DB_USERNAME`, and `DB_PASSWORD` for your deployment; do not use the example password in production.
```powershell
docker run --name tls-monitor -p 8085:8085 `
  -e DB_URL=jdbc:postgresql://host.docker.internal:5432/tls_monitoring_db `
  -e DB_USERNAME=postgres `
  -e DB_PASSWORD=your-database-password `
  tls-monitor
```
The application listens on port `8085` and runs with authentication enabled. For deployments where the database is not on the Docker host, use its reachable hostname or address in `DB_URL`.

### 6. Access the Application
- Local preview URL: **http://localhost:8085**
- Default Administrator Credentials:
  - **Username:** `admin`
  - **Password:** `admin123`
*(Account is bootstrapped with BCrypt hashing automatically on first start).*

---

## 🛡 Security Scanning Boundaries & Safe Scan Policy

To protect internal networks and adhere to cybersecurity best practices:
1. **Anti-SSRF Protection**: Rejects all loopbacks (`127.0.0.1`, `::1`), private RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local IPs, cloud metadata (`169.254.169.254`), and internal suffixes (`.internal`, `.local`).
2. **Safe Port & Strict Timeouts**: Inspects strictly over standard TLS port 443 with 6-second connection timeouts and 6-second socket read timeouts.
3. **Dual Handshake Inspection**: Performs standard TrustStore validation first. When an untrusted or self-signed certificate is encountered, gracefully captures the certificate chain and marks the finding rather than failing silently.
4. **Formula Injection Sanitization**: All Excel exports automatically sanitize cells starting with `=`, `+`, `-`, or `@` to neutralize CSV/Excel formula injection attacks.
5. **Severity Floor Rule**: If an endpoint contains any `HIGH` or `CRITICAL` finding (e.g. Hostname Mismatch, Expired Certificate), the target's overall risk posture is automatically elevated to reflect that severity floor.

---

## 🧪 Real Domains for Testing

| Target Domain | Category | Expected Findings & Posture |
|---|---|---|
| **`google.com`** | Real Production | TLS 1.3, Google Trust Services CA, **LOW Risk (0–15)** |
| **`github.com`** | Real Production | TLS 1.3, DigiCert CA, **LOW Risk (0–15)** |
| **`cloudflare.com`** | Real Production | TLS 1.3, Cloudflare Inc ECC CA, **LOW Risk (0–15)** |
| **`expired.badssl.com`** | Real Vulnerability Test | Expired Certificate, **CRITICAL Risk (80+)**, Triggers Alert |
| **`wrong.host.badssl.com`**| Real Vulnerability Test | Hostname Mismatch, **HIGH Risk (40+)**, Triggers Alert |
| **`self-signed.badssl.com`**| Real Vulnerability Test | Self-Signed / Untrusted Root, **CRITICAL Risk (75+)** |

---

## 🔌 REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/websites` | List all registered websites |
| `POST`| `/api/websites` | Register a new target website with SSRF validation |
| `DELETE`| `/api/websites/{id}` | Delete a website from inventory |
| `POST`| `/api/scans/{websiteId}` | Trigger an immediate TLS scan and risk evaluation |
| `GET` | `/api/scans/{websiteId}` | Retrieve full scan history for a website |
| `GET` | `/api/certificates/{websiteId}` | Retrieve latest X.509 certificate details |
| `GET` | `/api/risks/{websiteId}` | Retrieve current risk assessment & findings |
| `GET` | `/api/reports/{websiteId}/pdf?inline=true` | View audit PDF report in browser |
| `GET` | `/api/reports/{websiteId}/pdf?inline=false`| Download audit PDF report file |
| `GET` | `/api/reports/excel` | Download global 6-sheet Excel workbook |
| `GET` | `/api/alerts` | List all active security alerts |
| `PUT` | `/api/alerts/{id}/acknowledge` | Acknowledge an alert |
| `PUT` | `/api/alerts/{id}/resolve` | Mark an alert resolved |

---

## 📋 Running Tests

Execute the full suite of 58 unit, integration, and security hardening tests:

```powershell
.\mvnw.cmd test
```
