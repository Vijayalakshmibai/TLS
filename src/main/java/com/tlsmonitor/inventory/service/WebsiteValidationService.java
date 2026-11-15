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

    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
            "^(?=.{1,253}$)(?!-)[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,63}$"
    );

    public record NormalizedTarget(String domain, int port, String normalizedUrl) {}

    public NormalizedTarget normalizeAndValidate(String input) {
        if (input == null || input.trim().isEmpty()) {
            throw new InvalidDomainException("Target domain or URL cannot be blank.");
        }

        String raw = input.trim();
        // Check for IPv6 loopback or literals directly
        if (raw.equalsIgnoreCase("::1") || raw.equalsIgnoreCase("[::1]") || raw.equalsIgnoreCase("https://[::1]") || raw.equalsIgnoreCase("http://[::1]")) {
            throw new SSRFSecurityException("SSRF Policy Violation: Scanning loopback IPv6 address is prohibited (::1)");
        }

        String host;
        int port = 443;

        try {
            if (!raw.startsWith("http://") && !raw.startsWith("https://")) {
                raw = "https://" + raw;
            }
            URI uri = URI.create(raw);
            host = uri.getHost();
            if (host == null) {
                // Handle raw domain with port e.g. "example.com:443"
                String withoutScheme = raw.replaceFirst("^https?://", "");
                int slashIdx = withoutScheme.indexOf('/');
                if (slashIdx != -1) {
                    withoutScheme = withoutScheme.substring(0, slashIdx);
                }
                int colonIdx = withoutScheme.indexOf(':');
                if (colonIdx != -1) {
                    host = withoutScheme.substring(0, colonIdx);
                    port = Integer.parseInt(withoutScheme.substring(colonIdx + 1));
                } else {
                    host = withoutScheme;
                }
            } else if (uri.getPort() != -1) {
                port = uri.getPort();
            }
        } catch (Exception e) {
            throw new InvalidDomainException("Malformed URL or domain format: " + input);
        }

        if (host == null || host.isEmpty()) {
            throw new InvalidDomainException("Extracted host is empty from: " + input);
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

        // Anti-SSRF check against known internal names
        if (host.equalsIgnoreCase("localhost") ||
                host.equalsIgnoreCase("127.0.0.1") ||
                host.equalsIgnoreCase("::1") ||
                host.equalsIgnoreCase("metadata.google.internal") ||
                host.endsWith(".local") ||
                host.endsWith(".internal")) {
            throw new SSRFSecurityException("SSRF Policy Violation: Scanning internal or loopback hosts is prohibited (" + host + ")");
        }

        if (!DOMAIN_PATTERN.matcher(host).matches()) {
            // Check if it's an IPv4 address
            try {
                InetAddress addr = InetAddress.getByName(host);
                validateIPAgainstSSRF(addr);
            } catch (UnknownHostException e) {
                throw new InvalidDomainException("Invalid domain name syntax: " + host);
            }
        } else {
            // Resolve DNS and check all IPs for SSRF
            validateHostDNSAgainstSSRF(host);
        }

        String url = (port == 443) ? "https://" + host : "https://" + host + ":" + port;
        return new NormalizedTarget(host, port, url);
    }

    public void validateHostDNSAgainstSSRF(String host) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            if (addresses == null || addresses.length == 0) {
                throw new InvalidDomainException("Domain could not be resolved: " + host);
            }
            for (InetAddress address : addresses) {
                validateIPAgainstSSRF(address);
            }
        } catch (UnknownHostException e) {
            throw new InvalidDomainException("DNS resolution failed for domain: " + host);
        }
    }

    private void validateIPAgainstSSRF(InetAddress addr) {
        if (addr.isLoopbackAddress()) {
            throw new SSRFSecurityException("SSRF Policy: Loopback addresses are blocked (" + addr.getHostAddress() + ")");
        }
        if (addr.isSiteLocalAddress()) {
            throw new SSRFSecurityException("SSRF Policy: Private RFC1918 addresses are blocked (" + addr.getHostAddress() + ")");
        }
        if (addr.isLinkLocalAddress()) {
            throw new SSRFSecurityException("SSRF Policy: Link-local addresses are blocked (" + addr.getHostAddress() + ")");
        }
        if (addr.isMulticastAddress()) {
            throw new SSRFSecurityException("SSRF Policy: Multicast addresses are blocked (" + addr.getHostAddress() + ")");
        }
        if (addr.isAnyLocalAddress()) {
            throw new SSRFSecurityException("SSRF Policy: Wildcard local addresses are blocked (" + addr.getHostAddress() + ")");
        }

        byte[] b = addr.getAddress();
        // Check AWS / cloud metadata 169.254.169.254
        if (b.length == 4 && (b[0] & 0xFF) == 169 && (b[1] & 0xFF) == 254) {
            throw new SSRFSecurityException("SSRF Policy: Cloud metadata IP range 169.254.x.x is blocked.");
        }
    }
}
