package com.tlsmonitor.reporting.view;

import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.alerts.service.AlertService;
import com.tlsmonitor.dashboard.view.MainLayout;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.repository.CertificateDetailsRepository;
import com.tlsmonitor.inspection.repository.TLSScanResultRepository;
import com.tlsmonitor.inspection.service.TLSInspectionService;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.entity.SecurityFinding;
import com.tlsmonitor.risk.repository.RiskAssessmentRepository;
import com.tlsmonitor.risk.repository.SecurityFindingRepository;
import com.tlsmonitor.risk.service.RiskAnalyzer;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.combobox.ComboBox;
import com.vaadin.flow.component.dialog.Dialog;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.html.*;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.tabs.TabSheet;
import com.tlsmonitor.common.view.WebsiteSelection;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import jakarta.annotation.security.PermitAll;

import java.time.format.DateTimeFormatter;
import java.util.List;

@Route(value = "reports", layout = MainLayout.class)
@PageTitle("Reports & Exports | Fresh TLS Monitor")
@PermitAll
public class ReportsView extends VerticalLayout implements BeforeEnterObserver {

    private final WebsiteService websiteService;
    private final TLSInspectionService inspectionService;
    private final RiskAnalyzer riskAnalyzer;
    private final AlertService alertService;
    private final TLSScanResultRepository scanRepository;
    private final CertificateDetailsRepository certRepository;
    private final RiskAssessmentRepository riskRepository;
    private final SecurityFindingRepository findingRepository;
    private final ComboBox<Website> reportWebsiteSelect = new ComboBox<>("Select Target Website");

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    public ReportsView(WebsiteService websiteService,
                       TLSInspectionService inspectionService,
                       RiskAnalyzer riskAnalyzer,
                       AlertService alertService,
                       TLSScanResultRepository scanRepository,
                       CertificateDetailsRepository certRepository,
                       RiskAssessmentRepository riskRepository,
                       SecurityFindingRepository findingRepository) {
        this.websiteService = websiteService;
        this.inspectionService = inspectionService;
        this.riskAnalyzer = riskAnalyzer;
        this.alertService = alertService;
        this.scanRepository = scanRepository;
        this.certRepository = certRepository;
        this.riskRepository = riskRepository;
        this.findingRepository = findingRepository;

        setSizeFull();
        setPadding(true);
        setSpacing(true);

        H2 header = new H2("📑 Security Reporting & Audit Exports");
        header.getStyle().set("margin-top", "0");
        Paragraph subtitle = new Paragraph("View inline reports directly in the browser or export official audit-ready PDF documents and multi-sheet Excel workbooks.");
        subtitle.getStyle().set("color", "#64748b");

        HorizontalLayout cards = createDownloadCards();
        Div statsPanel = createSummaryStatistics();

        add(header, subtitle, cards, statsPanel);
    }

    @Override
    public void beforeEnter(BeforeEnterEvent event) {
        List<Website> websites = websiteService.getAllWebsites();
        reportWebsiteSelect.setItems(websites);
        WebsiteSelection.resolve(event, websites).ifPresent(id -> websites.stream()
                .filter(w -> w.getId().equals(id))
                .findFirst()
                .ifPresent(reportWebsiteSelect::setValue));
    }

    private HorizontalLayout createDownloadCards() {
        HorizontalLayout layout = new HorizontalLayout();
        layout.setWidthFull();
        layout.setSpacing(true);

        // 1. PDF Report Card
        Div pdfCard = new Div();
        pdfCard.getStyle().set("background-color", "#ffffff");
        pdfCard.getStyle().set("border", "1px solid #e2e8f0");
        pdfCard.getStyle().set("border-radius", "8px");
        pdfCard.getStyle().set("padding", "1.5rem");
        pdfCard.getStyle().set("flex", "1");

        H3 pdfTitle = new H3("📄 PDF Security Audit Report");
        pdfTitle.getStyle().set("margin-top", "0");
        Paragraph pdfDesc = new Paragraph("Inspect or download a formal single-domain PDF audit report featuring TLS handshake configuration, X.509 certificate hierarchy, and risk remediations.");

        ComboBox<Website> websiteSelect = reportWebsiteSelect;
        websiteSelect.setItemLabelGenerator(Website::getDomain);
        websiteSelect.setWidthFull();
        List<Website> websites = websiteService.getAllWebsites();
        websiteSelect.setItems(websites);
        if (!websites.isEmpty()) {
            websiteSelect.setValue(websites.get(0));
        }
        websiteSelect.addValueChangeListener(e -> {
            if (e.getValue() != null) {
                WebsiteSelection.remember(e.getValue().getId());
            }
        });

        Button viewPdfBtn = new Button("View PDF Report", VaadinIcon.EYE.create(), e -> {
            Website site = websiteSelect.getValue();
            if (site != null) {
                UI.getCurrent().getPage().open("/api/reports/" + site.getId() + "/pdf?inline=true", "_blank");
            }
        });
        viewPdfBtn.addThemeVariants(ButtonVariant.LUMO_PRIMARY);

        Button downloadPdfBtn = new Button("Download PDF", VaadinIcon.DOWNLOAD.create(), e -> {
            Website site = websiteSelect.getValue();
            if (site != null) {
                UI.getCurrent().getPage().open("/api/reports/" + site.getId() + "/pdf?inline=false", "_blank");
            }
        });
        downloadPdfBtn.addThemeVariants(ButtonVariant.LUMO_CONTRAST);

        HorizontalLayout pdfBtnRow = new HorizontalLayout(viewPdfBtn, downloadPdfBtn);
        pdfBtnRow.setSpacing(true);
        pdfBtnRow.getStyle().set("margin-top", "1rem");

        pdfCard.add(pdfTitle, pdfDesc, websiteSelect, pdfBtnRow);

        // 2. Excel Report Card
        Div excelCard = new Div();
        excelCard.getStyle().set("background-color", "#ffffff");
        excelCard.getStyle().set("border", "1px solid #e2e8f0");
        excelCard.getStyle().set("border-radius", "8px");
        excelCard.getStyle().set("padding", "1.5rem");
        excelCard.getStyle().set("flex", "1");

        H3 excelTitle = new H3("📊 Multi-Sheet Excel Workbook");
        excelTitle.getStyle().set("margin-top", "0");
        Paragraph excelDesc = new Paragraph("Preview the 6 audit sheets directly in your browser or export a fully styled Microsoft Excel (.xlsx) workbook for offline analysis.");

        Button viewExcelDataBtn = new Button("View Report Data (Sheets)", VaadinIcon.TABLE.create(), e -> openSheetViewerDialog());
        viewExcelDataBtn.addThemeVariants(ButtonVariant.LUMO_PRIMARY, ButtonVariant.LUMO_SUCCESS);

        Button downloadExcelBtn = new Button("Download Excel (.xlsx)", VaadinIcon.DOWNLOAD.create(), e -> {
            UI.getCurrent().getPage().open("/api/reports/excel", "_blank");
        });
        downloadExcelBtn.addThemeVariants(ButtonVariant.LUMO_CONTRAST);

        HorizontalLayout excelBtnRow = new HorizontalLayout(viewExcelDataBtn, downloadExcelBtn);
        excelBtnRow.setSpacing(true);
        excelBtnRow.getStyle().set("margin-top", "2.75rem");

        excelCard.add(excelTitle, excelDesc, excelBtnRow);

        layout.add(pdfCard, excelCard);
        return layout;
    }

    private void openSheetViewerDialog() {
        Dialog dialog = new Dialog();
        dialog.setHeaderTitle("📊 Global Security Audit Report - Sheet View");
        dialog.setWidth("90vw");
        dialog.setHeight("80vh");

        TabSheet tabSheet = new TabSheet();
        tabSheet.setSizeFull();

        // Sheet 1: Website Inventory
        Grid<Website> websiteGrid = new Grid<>(Website.class, false);
        websiteGrid.setSizeFull();
        websiteGrid.addColumn(Website::getId).setHeader("ID").setWidth("70px");
        websiteGrid.addColumn(Website::getDomain).setHeader("Domain").setAutoWidth(true);
        websiteGrid.addColumn(Website::getUrl).setHeader("URL").setAutoWidth(true);
        websiteGrid.addColumn(Website::getPort).setHeader("Port").setWidth("90px");
        websiteGrid.addColumn(Website::getStatus).setHeader("Status").setWidth("110px");
        websiteGrid.addColumn(w -> w.getLastScannedAt() != null ? w.getLastScannedAt().format(DATE_FORMATTER) : "N/A").setHeader("Last Scanned").setAutoWidth(true);
        websiteGrid.setItems(websiteService.getAllWebsites());
        tabSheet.add("1. Website Inventory", websiteGrid);

        // Sheet 2: Certificate Details
        Grid<CertificateDetails> certGrid = new Grid<>(CertificateDetails.class, false);
        certGrid.setSizeFull();
        certGrid.addColumn(CertificateDetails::getWebsiteId).setHeader("Site ID").setWidth("80px");
        certGrid.addColumn(CertificateDetails::getSubject).setHeader("Subject").setAutoWidth(true);
        certGrid.addColumn(CertificateDetails::getIssuer).setHeader("Issuer CA").setAutoWidth(true);
        certGrid.addColumn(c -> c.getDaysRemaining() + " days").setHeader("Days Left").setWidth("110px");
        certGrid.addColumn(c -> c.isExpired() ? "EXPIRED" : (c.isNotYetValid() ? "NOT YET VALID" : "VALID")).setHeader("Status").setWidth("120px");
        certGrid.addColumn(c -> c.getKeySize() + " bits (" + c.getPublicKeyAlgorithm() + ")").setHeader("Public Key").setAutoWidth(true);
        certGrid.setItems(certRepository.findAll());
        tabSheet.add("2. Certificate Details", certGrid);

        // Sheet 3: TLS Inspections
        Grid<TLSScanResult> scanGrid = new Grid<>(TLSScanResult.class, false);
        scanGrid.setSizeFull();
        scanGrid.addColumn(TLSScanResult::getDomain).setHeader("Domain").setAutoWidth(true);
        scanGrid.addColumn(TLSScanResult::getConnectionStatus).setHeader("Status").setWidth("110px");
        scanGrid.addColumn(TLSScanResult::getTlsVersion).setHeader("Negotiated TLS").setWidth("120px");
        scanGrid.addColumn(TLSScanResult::getCipherSuite).setHeader("Cipher Suite").setAutoWidth(true);
        scanGrid.addColumn(s -> s.getHostnameValidationStatus().name().replace('_', ' ')).setHeader("Hostname").setWidth("110px");
        scanGrid.addColumn(s -> s.getTrustValidationStatus().name().replace('_', ' ')).setHeader("Trust Chain").setWidth("110px");
        scanGrid.addColumn(s -> s.getResponseTimeMs() + " ms").setHeader("Latency").setWidth("100px");
        scanGrid.setItems(scanRepository.findAll());
        tabSheet.add("3. TLS Inspections", scanGrid);

        // Sheet 4: Risk Assessments
        Grid<RiskAssessment> riskGrid = new Grid<>(RiskAssessment.class, false);
        riskGrid.setSizeFull();
        riskGrid.addColumn(RiskAssessment::getWebsiteId).setHeader("Site ID").setWidth("80px");
        riskGrid.addColumn(r -> r.getTotalScore() + "/100").setHeader("Score").setWidth("90px");
        riskGrid.addColumn(RiskAssessment::getRiskLevel).setHeader("Level").setWidth("110px");
        riskGrid.addColumn(RiskAssessment::getFindingsCount).setHeader("Findings Count").setWidth("120px");
        riskGrid.addColumn(r -> r.getAssessedAt() != null ? r.getAssessedAt().format(DATE_FORMATTER) : "").setHeader("Assessed At").setAutoWidth(true);
        riskGrid.setItems(riskRepository.findAll());
        tabSheet.add("4. Risk Assessments", riskGrid);

        // Sheet 5: Security Findings
        Grid<SecurityFinding> findingGrid = new Grid<>(SecurityFinding.class, false);
        findingGrid.setSizeFull();
        findingGrid.addColumn(SecurityFinding::getRuleCode).setHeader("Rule").setWidth("120px");
        findingGrid.addColumn(SecurityFinding::getSeverity).setHeader("Severity").setWidth("100px");
        findingGrid.addColumn(SecurityFinding::getTitle).setHeader("Issue Title").setAutoWidth(true);
        findingGrid.addColumn(SecurityFinding::getRecommendation).setHeader("Remediation Recommendation").setAutoWidth(true);
        findingGrid.setItems(findingRepository.findAll());
        tabSheet.add("5. Security Findings", findingGrid);

        // Sheet 6: Alert History
        Grid<Alert> alertGrid = new Grid<>(Alert.class, false);
        alertGrid.setSizeFull();
        alertGrid.addColumn(Alert::getDomain).setHeader("Domain").setAutoWidth(true);
        alertGrid.addColumn(Alert::getAlertType).setHeader("Type").setAutoWidth(true);
        alertGrid.addColumn(Alert::getSeverity).setHeader("Severity").setWidth("100px");
        alertGrid.addColumn(Alert::getStatus).setHeader("Status").setWidth("110px");
        alertGrid.addColumn(Alert::getMessage).setHeader("Alert Message").setAutoWidth(true);
        alertGrid.setItems(alertService.getAllAlerts());
        tabSheet.add("6. Alert History", alertGrid);

        Button closeBtn = new Button("Close", e -> dialog.close());
        closeBtn.addThemeVariants(ButtonVariant.LUMO_PRIMARY);
        dialog.getFooter().add(closeBtn);

        dialog.add(tabSheet);
        dialog.open();
    }

    private Div createSummaryStatistics() {
        Div container = new Div();
        container.getStyle().set("background-color", "#f8fafc");
        container.getStyle().set("border", "1px solid #e2e8f0");
        container.getStyle().set("border-radius", "8px");
        container.getStyle().set("padding", "1.5rem");
        container.getStyle().set("margin-top", "1.5rem");
        container.setWidthFull();

        H3 title = new H3("Current System Audit Metrics");
        title.getStyle().set("margin-top", "0");

        HorizontalLayout stats = new HorizontalLayout();
        stats.setWidthFull();
        stats.setJustifyContentMode(FlexComponent.JustifyContentMode.AROUND);

        stats.add(createStatItem("Total Targets", String.valueOf(websiteService.countTotalWebsites())));
        stats.add(createStatItem("Active Monitored", String.valueOf(websiteService.countActiveWebsites())));
        stats.add(createStatItem("Successful Scans", String.valueOf(inspectionService.countSuccessfulScans())));
        stats.add(createStatItem("Critical Risks", String.valueOf(riskAnalyzer.countCriticalRisks())));
        stats.add(createStatItem("Open Alerts", String.valueOf(alertService.countActiveAlerts())));

        container.add(title, stats);
        return container;
    }

    private VerticalLayout createStatItem(String label, String value) {
        VerticalLayout v = new VerticalLayout();
        v.setAlignItems(FlexComponent.Alignment.CENTER);
        v.setPadding(false);
        v.setSpacing(false);

        Span val = new Span(value);
        val.getStyle().set("font-size", "1.75rem");
        val.getStyle().set("font-weight", "700");
        val.getStyle().set("color", "#1e3a8a");

        Span lbl = new Span(label);
        lbl.getStyle().set("font-size", "0.85rem");
        lbl.getStyle().set("color", "#64748b");

        v.add(val, lbl);
        return v;
    }
}
