package com.tlsmonitor.risk.view;

import com.tlsmonitor.dashboard.view.MainLayout;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.service.TLSInspectionService;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.service.RiskAnalyzer;
import com.vaadin.flow.component.combobox.ComboBox;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.html.*;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.select.Select;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import jakarta.annotation.security.PermitAll;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;

@Route(value = "risks", layout = MainLayout.class)
@PageTitle("Risk Analysis | Fresh TLS Monitor")
@PermitAll
public class RiskAnalysisView extends VerticalLayout {

    private final WebsiteService websiteService;
    private final TLSInspectionService inspectionService;
    private final RiskAnalyzer riskAnalyzer;

    private final ComboBox<Website> websiteSelect = new ComboBox<>("Select Monitored Website");
    private final Select<String> severityFilter = new Select<>();
    private final Div scoreCardContainer = new Div();
    private final Grid<SecurityFinding> findingsGrid = new Grid<>(SecurityFinding.class, false);

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public RiskAnalysisView(WebsiteService websiteService,
                            TLSInspectionService inspectionService,
                            RiskAnalyzer riskAnalyzer) {
        this.websiteService = websiteService;
        this.inspectionService = inspectionService;
        this.riskAnalyzer = riskAnalyzer;

        setSizeFull();
        setPadding(true);
        setSpacing(true);

        H2 header = new H2("🛡️ Security Risk Analysis & Vulnerability Scoring");
        header.getStyle().set("margin-top", "0");
        Paragraph subtitle = new Paragraph("Evaluates certificate expiry, cryptographic key lengths, signature hashing algorithms, hostname validity, and legacy TLS versions against transparent security rules.");
        subtitle.getStyle().set("color", "#64748b");

        HorizontalLayout filterRow = createFilterRow();
        configureFindingsGrid();

        scoreCardContainer.setWidthFull();

        add(header, subtitle, filterRow, scoreCardContainer, new H3("Detected Security Findings & Action Items"), findingsGrid);
    }

    private HorizontalLayout createFilterRow() {
        websiteSelect.setItemLabelGenerator(w -> w.getDomain() + " (" + w.getUrl() + ")");
        websiteSelect.setWidth("380px");
        List<Website> websites = websiteService.getAllWebsites();
        websiteSelect.setItems(websites);
        if (!websites.isEmpty()) {
            websiteSelect.setValue(websites.get(0));
        }

        severityFilter.setLabel("Filter by Severity");
        severityFilter.setItems("ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW");
        severityFilter.setValue("ALL");
        severityFilter.setWidth("180px");

        websiteSelect.addValueChangeListener(e -> loadWebsiteRiskData());
        severityFilter.addValueChangeListener(e -> loadWebsiteRiskData());

        HorizontalLayout row = new HorizontalLayout(websiteSelect, severityFilter);
        row.setDefaultVerticalComponentAlignment(FlexComponent.Alignment.END);
        row.setSpacing(true);

        if (!websites.isEmpty()) {
            loadWebsiteRiskData();
        }
        return row;
    }

    private void configureFindingsGrid() {
        findingsGrid.setSizeFull();

        findingsGrid.addComponentColumn(f -> {
            Span badge = new Span(f.getSeverity());
            badge.getStyle().set("padding", "0.2rem 0.5rem");
            badge.getStyle().set("border-radius", "4px");
            badge.getStyle().set("font-weight", "600");
            badge.getStyle().set("font-size", "0.8rem");

            switch (f.getSeverity().toUpperCase()) {
                case "CRITICAL" -> {
                    badge.getStyle().set("color", "#991b1b");
                    badge.getStyle().set("background-color", "#fee2e2");
                }
                case "HIGH" -> {
                    badge.getStyle().set("color", "#c2410c");
                    badge.getStyle().set("background-color", "#ffedd5");
                }
                case "MEDIUM" -> {
                    badge.getStyle().set("color", "#854d0e");
                    badge.getStyle().set("background-color", "#fef9c3");
                }
                default -> {
                    badge.getStyle().set("color", "#15803d");
                    badge.getStyle().set("background-color", "#dcfce7");
                }
            }
            return badge;
        }).setHeader("Severity").setWidth("110px");

        findingsGrid.addColumn(SecurityFinding::getRuleCode).setHeader("Rule").setWidth("120px");
        findingsGrid.addColumn(SecurityFinding::getTitle).setHeader("Finding").setAutoWidth(true);
        findingsGrid.addColumn(SecurityFinding::getEvidence).setHeader("Evidence").setAutoWidth(true);
        findingsGrid.addColumn(SecurityFinding::getRecommendation).setHeader("Remediation Guidance").setAutoWidth(true);
        findingsGrid.addColumn(f -> f.getPoints() + " pts").setHeader("Impact").setWidth("90px");
    }

    private void loadWebsiteRiskData() {
        Website site = websiteSelect.getValue();
        if (site == null) {
            scoreCardContainer.removeAll();
            findingsGrid.setItems(List.of());
            return;
        }

        // Fetch latest scan and certificate to calculate or display assessment
        Optional<TLSScanResult> latestScan = inspectionService.getLatestScan(site.getId());
        if (latestScan.isEmpty()) {
            scoreCardContainer.removeAll();
            Div emptyMsg = new Div(new Paragraph("No scan completed yet for " + site.getDomain() + ". Run an inspection from the Website Inventory or TLS Inspection page."));
            emptyMsg.getStyle().set("color", "#64748b");
            scoreCardContainer.add(emptyMsg);
            findingsGrid.setItems(List.of());
            return;
        }

        TLSScanResult scan = latestScan.get();
        Optional<CertificateDetails> cert = inspectionService.getCertificateByScanId(scan.getId());

        // Run or fetch risk analysis
        RiskAnalyzer.AnalysisResult result = riskAnalyzer.analyzeAndPersist(scan, cert.orElse(null));
        displayScoreCard(site.getDomain(), result.assessment());

        List<SecurityFinding> findings = result.findings();
        String filter = severityFilter.getValue();
        if (filter != null && !"ALL".equalsIgnoreCase(filter)) {
            findings = findings.stream().filter(f -> f.getSeverity().equalsIgnoreCase(filter)).toList();
        }
        findingsGrid.setItems(findings);
    }

    private void displayScoreCard(String domain, RiskAssessment assessment) {
        scoreCardContainer.removeAll();

        Div card = new Div();
        card.getStyle().set("background-color", "#ffffff");
        card.getStyle().set("border", "1px solid #e2e8f0");
        card.getStyle().set("border-radius", "8px");
        card.getStyle().set("padding", "1.5rem");
        card.getStyle().set("margin-top", "1rem");

        HorizontalLayout content = new HorizontalLayout();
        content.setDefaultVerticalComponentAlignment(FlexComponent.Alignment.CENTER);
        content.setJustifyContentMode(FlexComponent.JustifyContentMode.BETWEEN);
        content.setWidthFull();

        VerticalLayout textLayout = new VerticalLayout();
        textLayout.setPadding(false);
        textLayout.setSpacing(false);

        H3 title = new H3("Overall Security Score for " + domain);
        title.getStyle().set("margin", "0 0 0.5rem 0");

        Paragraph meta = new Paragraph("Assessment Timestamp: " + assessment.getAssessedAt().format(DATE_FORMATTER) + " | Rule Set: v" + assessment.getRuleSetVersion() + " | Total Issues: " + assessment.getFindingsCount());
        meta.getStyle().set("color", "#64748b");
        meta.getStyle().set("margin", "0");

        textLayout.add(title, meta);

        VerticalLayout scorePill = new VerticalLayout();
        scorePill.setAlignItems(FlexComponent.Alignment.CENTER);
        scorePill.setPadding(false);
        scorePill.setSpacing(false);

        Span scoreText = new Span(assessment.getTotalScore() + "/100");
        scoreText.getStyle().set("font-size", "2.25rem");
        scoreText.getStyle().set("font-weight", "800");

        Span levelBadge = new Span(assessment.getRiskLevel() + " RISK");
        levelBadge.getStyle().set("font-weight", "700");
        levelBadge.getStyle().set("padding", "0.25rem 0.75rem");
        levelBadge.getStyle().set("border-radius", "6px");
        levelBadge.getStyle().set("font-size", "0.9rem");

        switch (assessment.getRiskLevel().toUpperCase()) {
            case "CRITICAL" -> {
                scoreText.getStyle().set("color", "#dc2626");
                levelBadge.getStyle().set("color", "#ffffff");
                levelBadge.getStyle().set("background-color", "#dc2626");
            }
            case "HIGH" -> {
                scoreText.getStyle().set("color", "#ea580c");
                levelBadge.getStyle().set("color", "#ffffff");
                levelBadge.getStyle().set("background-color", "#ea580c");
            }
            case "MEDIUM" -> {
                scoreText.getStyle().set("color", "#ca8a04");
                levelBadge.getStyle().set("color", "#ffffff");
                levelBadge.getStyle().set("background-color", "#ca8a04");
            }
            default -> {
                scoreText.getStyle().set("color", "#16a34a");
                levelBadge.getStyle().set("color", "#ffffff");
                levelBadge.getStyle().set("background-color", "#16a34a");
            }
        }

        scorePill.add(scoreText, levelBadge);
        content.add(textLayout, scorePill);
        card.add(content);
        scoreCardContainer.add(card);
    }
}
