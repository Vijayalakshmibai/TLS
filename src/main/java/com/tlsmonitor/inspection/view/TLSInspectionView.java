package com.tlsmonitor.inspection.view;

import com.tlsmonitor.dashboard.view.MainLayout;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.entity.ValidationStatus;
import com.tlsmonitor.inspection.service.ScanOrchestratorService;
import com.tlsmonitor.inspection.service.TLSInspectionService;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.tlsmonitor.common.view.WebsiteSelection;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.html.*;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.select.Select;
import com.vaadin.flow.router.*;
import jakarta.annotation.security.PermitAll;

import java.time.format.DateTimeFormatter;
import java.util.List;

@Route(value = "inspection", layout = MainLayout.class)
@PageTitle("TLS Inspection | Fresh TLS Monitor")
@PermitAll
public class TLSInspectionView extends VerticalLayout implements BeforeEnterObserver {

    private final WebsiteService websiteService;
    private final TLSInspectionService inspectionService;
    private final ScanOrchestratorService scanOrchestratorService;

    private final Select<Website> websiteSelect = new Select<>();
    private final Button scanBtn = new Button("Inspect TLS Configuration", VaadinIcon.SEARCH.create());
    private final Div resultsContainer = new Div();
    private final Grid<TLSScanResult> historyGrid = new Grid<>(TLSScanResult.class, false);

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public TLSInspectionView(WebsiteService websiteService,
                             TLSInspectionService inspectionService,
                             ScanOrchestratorService scanOrchestratorService) {
        this.websiteService = websiteService;
        this.inspectionService = inspectionService;
        this.scanOrchestratorService = scanOrchestratorService;

        setSizeFull();
        setPadding(true);
        setSpacing(true);

        H2 header = new H2("🔍 TLS Certificate & Configuration Inspector");
        header.getStyle().set("margin-top", "0");
        Paragraph subtitle = new Paragraph("Connects directly to each website over its configured port using Java JSSE, evaluates TLS protocol negotiations, and validates X.509 certificate chains.");
        subtitle.getStyle().set("color", "#64748b");

        HorizontalLayout selectorRow = createSelectorRow();
        configureHistoryGrid();

        resultsContainer.setWidthFull();

        add(header, subtitle, selectorRow, resultsContainer, new H3("Inspection History"), historyGrid);
    }

    private HorizontalLayout createSelectorRow() {
        websiteSelect.setLabel("Select Monitored Website");
        websiteSelect.setItemLabelGenerator(w -> w.getDomain() + " (" + w.getUrl() + ")");
        websiteSelect.setWidth("380px");

        List<Website> websites = websiteService.getAllWebsites();
        websiteSelect.setItems(websites);
        if (!websites.isEmpty()) {
            websiteSelect.setValue(websites.get(0));
        }

        scanBtn.addThemeVariants(ButtonVariant.LUMO_PRIMARY);
        scanBtn.getStyle().set("margin-top", "auto");
        scanBtn.getStyle().set("margin-bottom", "4px");
        scanBtn.addClickListener(e -> executeInspection());

        websiteSelect.addValueChangeListener(e -> {
            if (e.getValue() != null) {
                WebsiteSelection.remember(e.getValue().getId());
                loadWebsiteHistory(e.getValue().getId());
            }
        });

        HorizontalLayout row = new HorizontalLayout(websiteSelect, scanBtn);
        row.setDefaultVerticalComponentAlignment(FlexComponent.Alignment.END);
        row.setSpacing(true);
        return row;
    }

    private void configureHistoryGrid() {
        historyGrid.setHeight("250px");
        historyGrid.setWidthFull();

        historyGrid.addColumn(r -> r.getDomain() + ":" + r.getPort()).setHeader("Target").setAutoWidth(true);
        historyGrid.addColumn(r -> r.getScannedAt() != null ? r.getScannedAt().format(DATE_FORMATTER) : "").setHeader("Scan Time").setAutoWidth(true);
        historyGrid.addColumn(TLSScanResult::getConnectionStatus).setHeader("Status").setWidth("120px");
        historyGrid.addColumn(TLSScanResult::getTlsVersion).setHeader("TLS Version").setWidth("120px");
        historyGrid.addColumn(TLSScanResult::getCipherSuite).setHeader("Cipher Suite").setAutoWidth(true);
        historyGrid.addColumn(r -> formatValidationStatus(r.getHostnameValidationStatus())).setHeader("Hostname").setWidth("110px");
        historyGrid.addColumn(r -> formatValidationStatus(r.getTrustValidationStatus())).setHeader("Trust Chain").setWidth("110px");
        historyGrid.addColumn(r -> r.getResponseTimeMs() + " ms").setHeader("Latency").setWidth("100px");
    }

    private void executeInspection() {
        Website site = websiteSelect.getValue();
        if (site == null) {
            Notification.show("Please select a website first.", 3000, Notification.Position.TOP_CENTER);
            return;
        }

        scanBtn.setEnabled(false);
        scanBtn.setText("Inspecting TLS handshake...");

        try {
            ScanOrchestratorService.ScanPipelineResult outcome = scanOrchestratorService.executeScanPipeline(site.getId());
            displayResults(outcome.scanResult(), outcome.certificateDetails());
            loadWebsiteHistory(site.getId());
            Notification.show("TLS inspection complete for " + site.getDomain() + " (Risk: " + outcome.riskAssessment().getRiskLevel() + ")",
                            3000, Notification.Position.TOP_CENTER)
                    .addThemeVariants(NotificationVariant.LUMO_SUCCESS);
        } catch (Exception ex) {
            Notification.show("Inspection error: " + ex.getMessage(), 5000, Notification.Position.TOP_CENTER)
                    .addThemeVariants(NotificationVariant.LUMO_ERROR);
        } finally {
            scanBtn.setEnabled(true);
            scanBtn.setText("Inspect TLS Configuration");
        }
    }

    private void displayResults(TLSScanResult scan, CertificateDetails cert) {
        resultsContainer.removeAll();

        Div card = new Div();
        card.getStyle().set("background-color", "#ffffff");
        card.getStyle().set("border", "1px solid #e2e8f0");
        card.getStyle().set("border-radius", "8px");
        card.getStyle().set("padding", "1.5rem");
        card.getStyle().set("box-shadow", "0 1px 3px rgba(0,0,0,0.05)");

        H3 statusTitle = new H3("Scan Findings for " + scan.getDomain() + ":" + scan.getPort() + " (" + scan.getConnectionStatus() + ")");
        statusTitle.getStyle().set("margin-top", "0");

        HorizontalLayout badges = new HorizontalLayout();
        badges.setSpacing(true);

        badges.add(createBadge("Protocol: " + scan.getTlsVersion(), scan.getTlsVersion() != null ? "#1e40af" : "#991b1b", "#eff6ff"));
        badges.add(createBadge("Cipher: " + scan.getCipherSuite(), "#15803d", "#f0fdf4"));
        badges.add(validationBadge("Hostname", scan.getHostnameValidationStatus(), "Verified Match", "Mismatch"));
        badges.add(validationBadge("Trust Chain", scan.getTrustValidationStatus(), "Trusted Root", "Untrusted"));
        badges.add(createBadge("Latency: " + scan.getResponseTimeMs() + " ms", "#475569", "#f1f5f9"));

        if (scan.isWeakProtocolDetected()) {
            badges.add(createBadge("WARNING: Deprecated TLS 1.0/1.1 Supported", "#dc2626", "#fee2e2"));
        }

        card.add(statusTitle, badges);

        if (cert != null) {
            Div certCard = new Div();
            certCard.getStyle().set("margin-top", "1.25rem");
            certCard.getStyle().set("background-color", "#f8fafc");
            certCard.getStyle().set("padding", "1rem");
            certCard.getStyle().set("border-radius", "6px");
            certCard.getStyle().set("border", "1px solid #cbd5e1");

            certCard.add(new H4("📜 X.509 Certificate Details"));
            certCard.add(createDetailLine("Subject DN:", cert.getSubject()));
            certCard.add(createDetailLine("Issuer CA:", cert.getIssuer()));
            certCard.add(createDetailLine("Valid Range (UTC):", cert.getValidFrom() + " to " + cert.getValidUntil()));
            certCard.add(createDetailLine("Days Remaining:", cert.getDaysRemaining() + " days" + (cert.isExpired() ? " (EXPIRED)" : "")));
            certCard.add(createDetailLine("Public Key:", cert.getPublicKeyAlgorithm() + " (" + cert.getKeySize() + " bits)"));
            certCard.add(createDetailLine("Signature Algorithm:", cert.getSignatureAlgorithm()));
            certCard.add(createDetailLine("Serial Number:", cert.getSerialNumber()));
            certCard.add(createDetailLine("SHA-256 Fingerprint:", cert.getSha256Fingerprint()));
            certCard.add(createDetailLine("Alternative Names (SAN):", cert.getSubjectAlternativeNames()));

            card.add(certCard);
        }

        resultsContainer.add(card);
    }

    private Paragraph createDetailLine(String label, String value) {
        Paragraph p = new Paragraph();
        p.getStyle().set("margin", "0.25rem 0");
        p.getStyle().set("font-size", "0.9rem");

        Span l = new Span(label + " ");
        l.getStyle().set("font-weight", "600");
        l.getStyle().set("color", "#334155");

        Span v = new Span(value != null && !value.isEmpty() ? value : "N/A");
        v.getStyle().set("color", "#0f172a");

        p.add(l, v);
        return p;
    }

    private Span createBadge(String text, String color, String bgColor) {
        Span badge = new Span(text);
        badge.getStyle().set("color", color);
        badge.getStyle().set("background-color", bgColor);
        badge.getStyle().set("padding", "0.25rem 0.6rem");
        badge.getStyle().set("border-radius", "4px");
        badge.getStyle().set("font-size", "0.85rem");
        badge.getStyle().set("font-weight", "600");
        return badge;
    }

    private Span validationBadge(String label, ValidationStatus status, String validText, String invalidText) {
        String text = status == ValidationStatus.VALID ? validText
                : status == ValidationStatus.INVALID ? invalidText : "Not Evaluated";
        String color = status == ValidationStatus.NOT_EVALUATED ? "#475569"
                : status == ValidationStatus.VALID ? "#15803d" : "#b91c1c";
        String background = status == ValidationStatus.NOT_EVALUATED ? "#f1f5f9"
                : status == ValidationStatus.VALID ? "#f0fdf4" : "#fef2f2";
        return createBadge(label + ": " + text, color, background);
    }

    private String formatValidationStatus(ValidationStatus status) {
        return status == null ? "NOT EVALUATED" : status.name().replace('_', ' ');
    }

    private void loadWebsiteHistory(Long websiteId) {
        List<TLSScanResult> history = inspectionService.getScanHistory(websiteId);
        historyGrid.setItems(history);
        if (!history.isEmpty()) {
            TLSScanResult latest = history.get(0);
            inspectionService.getCertificateByScanId(latest.getId()).ifPresent(c -> displayResults(latest, c));
        } else {
            resultsContainer.removeAll();
        }
    }

    @Override
    public void beforeEnter(BeforeEnterEvent event) {
        List<Website> websites = websiteService.getAllWebsites();
        WebsiteSelection.resolve(event, websites).ifPresent(id -> websites.stream()
                .filter(w -> w.getId().equals(id))
                .findFirst()
                .ifPresent(w -> {
                    websiteSelect.setValue(w);
                    loadWebsiteHistory(w.getId());
                }));
    }
}
