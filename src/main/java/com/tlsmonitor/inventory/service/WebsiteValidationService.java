package com.tlsmonitor.inventory.service;

import com.tlsmonitor.common.exception.InvalidDomainException;
import com.tlsmonitor.common.exception.SSRFSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

@Service
public class WebsiteValidationService {

    private static final Logger log = LoggerFactory.getLogger(WebsiteValidationService.class);

    @org.springframework.beans.factory.annotation.Value("${tlsmonitor.security.allow-loopback:false}")
    private boolean allowLoopback = false;

    public WebsiteValidationService() {
        this(false);
    }

    public WebsiteValidationService(boolean allowLoopback) {
        this.allowLoopback = allowLoopback;
    }

    public boolean isAllowLoopback() {
        return allowLoopback;
    }

    public void setAllowLoopback(boolean allowLoopback) {
        this.allowLoopback = allowLoopback;
    }

    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
            "^(?=.{1,253}$)(?!-)[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,63}$");

    @FunctionalInterface
    public interface DnsResolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    public static final DnsResolver DEFAULT_RESOLVER = InetAddress::getAllByName;

    public record NormalizedTarget(String domain, int port, String normalizedUrl, InetAddress validatedAddress) {
        public NormalizedTarget(String domain, int port, String normalizedUrl) {
            this(domain, port, normalizedUrl, null);
        }
    }

    public NormalizedTarget normalizeAndValidate(String input) {
        return normalizeAndValidate(input, DEFAULT_RESOLVER);
    }

    public NormalizedTarget normalizeAndValidate(String input, DnsResolver resolver) {
        if (input == null || input.trim().isEmpty()) {
            throw new InvalidDomainException("Target domain or URL cannot be blank.");
        }

        String raw = input.trim();

        // Check for unsupported schemes explicitly before URI parsing
        if (raw.contains("://")) {
            int schemeIdx = raw.indexOf("://");
            String scheme = raw.substring(0, schemeIdx).toLowerCase();
            if (!scheme.equals("http") && !scheme.equals("https")) {
                throw new InvalidDomainException(
                        "Unsupported URL scheme: '" + scheme + "'. Only HTTP and HTTPS schemes are supported.");
            }
        } else if (raw.contains(":") && !raw.contains(".") && !raw.startsWith("[")) {
            // e.g. "javascript:alert(1)" or "data:text/html" or "file:/etc"
            int colonIdx = raw.indexOf(':');
            String potentialScheme = raw.substring(0, colonIdx).toLowerCase();
            if (potentialScheme.equals("javascript") || potentialScheme.equals("data") ||
                    potentialScheme.equals("file") || potentialScheme.equals("ftp") ||
                    potentialScheme.equals("ldap") || potentialScheme.equals("gopher")) {
                throw new InvalidDomainException("Unsupported URL scheme: '" + potentialScheme
                        + "'. Only HTTP and HTTPS schemes are supported.");
            }
        }

        // Direct check for loopback IPv6 literals
        if (!allowLoopback && (raw.equalsIgnoreCase("::1") || raw.equalsIgnoreCase("[::1]") ||
                raw.equalsIgnoreCase("https://[::1]") || raw.equalsIgnoreCase("http://[::1]") ||
                raw.startsWith("[::1]:") || raw.startsWith("https://[::1]:") || raw.startsWith("http://[::1]:"))) {
            throw new SSRFSecurityException(
                    "SSRF Policy Violation: Scanning loopback IPv6 address is prohibited (::1)");
        }

        String host;
        int port = 443;

        try {
            String uriString = raw;
            if (!uriString.startsWith("http://") && !uriString.startsWith("https://")) {
                uriString = "https://" + uriString;
            }
            URI uri = URI.create(uriString);
            host = uri.getHost();

            if (host == null) {
                // Handle raw domain with port e.g. "example.com:443" or "[::1]:443"
                String withoutScheme = uriString.replaceFirst("^https?://", "");
                int slashIdx = withoutScheme.indexOf('/');
                if (slashIdx != -1) {
                    withoutScheme = withoutScheme.substring(0, slashIdx);
                }

                if (withoutScheme.startsWith("[") && withoutScheme.contains("]")) {
                    int closeBracket = withoutScheme.indexOf(']');
                    host = withoutScheme.substring(1, closeBracket);
                    if (withoutScheme.length() > closeBracket + 1 && withoutScheme.charAt(closeBracket + 1) == ':') {
                        port = parsePort(withoutScheme.substring(closeBracket + 2));
                    }
                } else {
                    int colonIdx = withoutScheme.lastIndexOf(':');
                    if (colonIdx != -1) {
                        host = withoutScheme.substring(0, colonIdx);
                        port = parsePort(withoutScheme.substring(colonIdx + 1));
                    } else {
                        host = withoutScheme;
                    }
                }
            } else if (uri.getPort() != -1) {
                port = uri.getPort();
            }
        } catch (InvalidDomainException ide) {
            throw ide;
        } catch (Exception e) {
            throw new InvalidDomainException("Malformed URL or domain format: " + input);
        }

        if (host == null || host.isEmpty()) {
            throw new InvalidDomainException("Extracted host is empty from: " + input);
        }

        // Strip IPv6 brackets if still enclosed
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        host = host.toLowerCase().trim();

        // Remove trailing dot if present
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }

        // Validate port range
        if (port <= 0 || port > 65535) {
            throw new InvalidDomainException("Port number out of range (1-65535): " + port);
        }

        // Anti-SSRF check against known internal hostnames and aliases
        if (!allowLoopback && (host.equalsIgnoreCase("localhost") ||
                host.equalsIgnoreCase("127.0.0.1") ||
                host.equalsIgnoreCase("::1") ||
                host.endsWith(".localhost"))) {
            throw new SSRFSecurityException(
                    "SSRF Policy Violation: Scanning internal or loopback host is prohibited (" + host + ")");
        }

        if (host.equalsIgnoreCase("metadata.google.internal") ||
                host.equalsIgnoreCase("instance-data") ||
                host.equalsIgnoreCase("metadata") ||
                host.endsWith(".local") ||
                host.endsWith(".internal") ||
                host.endsWith(".corp") ||
                host.endsWith(".lan") ||
                host.endsWith(".home") ||
                host.endsWith(".private") ||
                host.endsWith(".invalid")) {
            throw new SSRFSecurityException(
                    "SSRF Policy Violation: Scanning internal or metadata host is prohibited (" + host + ")");
        }

        InetAddress pinnedAddress = null;

        if (!DOMAIN_PATTERN.matcher(host).matches()) {
            // Check if it's an IP literal (IPv4 or IPv6)
            try {
                InetAddress addr = InetAddress.getByName(host);
                validateIPAgainstSSRF(addr);
                pinnedAddress = addr;
            } catch (SSRFSecurityException se) {
                throw se;
            } catch (UnknownHostException e) {
                throw new InvalidDomainException("Invalid domain name syntax: " + host);
            }
        } else {
            // Valid domain name syntax: resolve DNS and check all IPs for SSRF & DNS
            // rebinding
            InetAddress[] addresses = validateHostDNSAgainstSSRF(host, resolver);
            if (addresses != null && addresses.length > 0) {
                pinnedAddress = addresses[0];
            }
        }

        String url = (port == 443) ? "https://" + host : "https://" + host + ":" + port;
        return new NormalizedTarget(host, port, url, pinnedAddress);
    }

    private int parsePort(String portStr) {
        try {
            return Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            throw new InvalidDomainException("Invalid port number: " + portStr);
        }
    }

    public InetAddress[] validateHostDNSAgainstSSRF(String host) {
        return validateHostDNSAgainstSSRF(host, DEFAULT_RESOLVER);
    }

    public InetAddress[] validateHostDNSAgainstSSRF(String host, DnsResolver resolver) {
        try {
            DnsResolver activeResolver = (resolver != null) ? resolver : DEFAULT_RESOLVER;
            InetAddress[] addresses = activeResolver.resolve(host);
            if (addresses == null || addresses.length == 0) {
                throw new InvalidDomainException("Domain could not be resolved: " + host);
            }
            for (InetAddress address : addresses) {
                validateIPAgainstSSRF(address);
            }
            return addresses;
        } catch (SSRFSecurityException se) {
            throw se;
        } catch (UnknownHostException e) {
            throw new InvalidDomainException("DNS resolution failed for domain: " + host);
        }
    }

    public void validateIPAgainstSSRF(InetAddress addr) {
        if (addr == null) {
            throw new SSRFSecurityException("SSRF Policy: Null address cannot be validated.");
        }

        if (addr.isLoopbackAddress()) {
            if (!allowLoopback) {
                throw new SSRFSecurityException(
                        "SSRF Policy: Loopback addresses are blocked (" + addr.getHostAddress() + ")");
            }
            return;
        }
        if (addr.isSiteLocalAddress()) {
            throw new SSRFSecurityException(
                    "SSRF Policy: Private RFC1918 addresses are blocked (" + addr.getHostAddress() + ")");
        }
        if (addr.isLinkLocalAddress()) {
            throw new SSRFSecurityException("SSRF Policy: Link-local and cloud metadata range 169.254.x.x is blocked ("
                    + addr.getHostAddress() + ")");
        }
        if (addr.isMulticastAddress()) {
            throw new SSRFSecurityException(
                    "SSRF Policy: Multicast addresses are blocked (" + addr.getHostAddress() + ")");
        }
        if (addr.isAnyLocalAddress()) {
            throw new SSRFSecurityException(
                    "SSRF Policy: Wildcard local addresses are blocked (" + addr.getHostAddress() + ")");
        }

        byte[] b = addr.getAddress();

        // 1. IPv6 Address Checks
        if (b.length == 16) {
            // Check for IPv4-mapped IPv6 address (::ffff:x.x.x.x)
            boolean isIpv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (b[i] != 0) {
                    isIpv4Mapped = false;
                    break;
                }
            }
            if (isIpv4Mapped && (b[10] & 0xFF) == 0xFF && (b[11] & 0xFF) == 0xFF) {
                byte[] v4Bytes = new byte[4];
                System.arraycopy(b, 12, v4Bytes, 0, 4);
                try {
                    InetAddress unwrappedV4 = InetAddress.getByAddress(v4Bytes);
                    validateIPAgainstSSRF(unwrappedV4);
                } catch (UnknownHostException ignored) {
                }
                return;
            }

            // IPv6 Unique Local Address (ULA) fc00::/7 (fc00: - fdff:)
            if ((b[0] & 0xFE) == 0xFC) {
                throw new SSRFSecurityException("SSRF Policy: IPv6 Unique Local Addresses (fc00::/7) are blocked ("
                        + addr.getHostAddress() + ")");
            }

            // IPv6 Link-Local fe80::/10
            if ((b[0] & 0xFF) == 0xFE && (b[1] & 0xC0) == 0x80) {
                throw new SSRFSecurityException("SSRF Policy: IPv6 Link-Local addresses (fe80::/10) are blocked ("
                        + addr.getHostAddress() + ")");
            }

            // IPv6 Multicast ff00::/8
            if ((b[0] & 0xFF) == 0xFF) {
                throw new SSRFSecurityException(
                        "SSRF Policy: IPv6 Multicast addresses (ff00::/8) are blocked (" + addr.getHostAddress() + ")");
            }
            return;
        }

        // 2. IPv4 Address Checks
        if (b.length == 4) {
            int i0 = b[0] & 0xFF;
            int i1 = b[1] & 0xFF;
            int i2 = b[2] & 0xFF;
            int i3 = b[3] & 0xFF;

            // 0.0.0.0/8 (Current network)
            if (i0 == 0) {
                throw new SSRFSecurityException("SSRF Policy: Current network addresses (0.0.0.0/8) are blocked ("
                        + addr.getHostAddress() + ")");
            }

            // 10.0.0.0/8 (Private RFC 1918)
            if (i0 == 10) {
                throw new SSRFSecurityException(
                        "SSRF Policy: Private RFC1918 addresses are blocked (" + addr.getHostAddress() + ")");
            }

            // 100.64.0.0/10 (Shared Address Space / CGNAT RFC 6598)
            if (i0 == 100 && (i1 >= 64 && i1 <= 127)) {
                throw new SSRFSecurityException(
                        "SSRF Policy: Shared address space (100.64.0.0/10) is blocked (" + addr.getHostAddress() + ")");
            }

            // 127.0.0.0/8 (Loopback)
            if (i0 == 127) {
                throw new SSRFSecurityException(
                        "SSRF Policy: Loopback addresses are blocked (" + addr.getHostAddress() + ")");
            }

            // 169.254.0.0/16 (Link-local & AWS/GCP/Azure Metadata 169.254.169.254)
            if (i0 == 169 && i1 == 254) {
                throw new SSRFSecurityException(
                        "SSRF Policy: Link-local and cloud metadata range 169.254.x.x is blocked ("
                                + addr.getHostAddress() + ")");
            }

            // 172.16.0.0/12 (Private RFC 1918)
            if (i0 == 172 && (i1 >= 16 && i1 <= 31)) {
                throw new SSRFSecurityException(
                        "SSRF Policy: Private RFC1918 addresses are blocked (" + addr.getHostAddress() + ")");
            }

            // 192.0.0.0/24 (IETF protocol assignments)
            if (i0 == 192 && i1 == 0 && i2 == 0) {
                throw new SSRFSecurityException("SSRF Policy: IETF protocol assignments (192.0.0.0/24) are blocked ("
                        + addr.getHostAddress() + ")");
            }

            // 192.168.0.0/16 (Private RFC 1918)
            if (i0 == 192 && i1 == 168) {
                throw new SSRFSecurityException(
                        "SSRF Policy: Private RFC1918 addresses are blocked (" + addr.getHostAddress() + ")");
            }

            // 198.18.0.0/15 (Benchmarking)
            if (i0 == 198 && (i1 == 18 || i1 == 19)) {
                throw new SSRFSecurityException(
                        "SSRF Policy: Benchmark test range (198.18.0.0/15) is blocked (" + addr.getHostAddress() + ")");
            }

            // 224.0.0.0/4 (Multicast 224.0.0.0 - 239.255.255.255)
            if (i0 >= 224 && i0 <= 239) {
                throw new SSRFSecurityException(
                        "SSRF Policy: Multicast addresses are blocked (" + addr.getHostAddress() + ")");
            }

            // 240.0.0.0/4 (Reserved for future use & 255.255.255.255 broadcast)
            if (i0 >= 240) {
                throw new SSRFSecurityException(
                        "SSRF Policy: Reserved / broadcast addresses (240.0.0.0/4) are blocked ("
                                + addr.getHostAddress() + ")");
            }
        }
    }

    public NormalizedTarget validateRedirectTarget(String currentUrl, String locationHeader) {
        return validateRedirectTarget(currentUrl, locationHeader, DEFAULT_RESOLVER);
    }

    public NormalizedTarget validateRedirectTarget(String currentUrl, String locationHeader, DnsResolver resolver) {
        if (locationHeader == null || locationHeader.trim().isEmpty()) {
            throw new SSRFSecurityException("Redirect target is empty.");
        }
        String trimmedLocation = locationHeader.trim();

        URI targetUri;
        try {
            if (currentUrl != null && !currentUrl.trim().isEmpty()) {
                URI baseUri = URI.create(currentUrl.trim());
                targetUri = baseUri.resolve(trimmedLocation);
            } else {
                targetUri = URI.create(trimmedLocation);
            }
        } catch (Exception e) {
            throw new SSRFSecurityException("Malformed redirect location: " + locationHeader);
        }

        String scheme = targetUri.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
            throw new SSRFSecurityException(
                    "SSRF Policy Violation: Redirect to non-HTTP/HTTPS scheme '" + scheme + "' is blocked.");
        }

        // Validate the resolved target URL against the full SSRF policy
        return normalizeAndValidate(targetUri.toString(), resolver);
    }
}
