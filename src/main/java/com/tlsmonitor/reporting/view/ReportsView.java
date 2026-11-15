package com.tlsmonitor.reporting.view;

import com.tlsmonitor.alerts.service.AlertService;
import com.tlsmonitor.dashboard.view.MainLayout;
import com.tlsmonitor.inspection.service.TLSInspectionService;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.tlsmonitor.risk.service.RiskAnalyzer;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.combobox.ComboBox;
import com.vaadin.flow.component.html.*;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.StreamResource;
import jakarta.annotation.security.PermitAll;

import java.io.ByteArrayInputStream;
import java.util.List;

@Route(value = "reports", layout = MainLayout.class)
@PageTitle("Reports & Exports | Fresh TLS Monitor")
@PermitAll
public class ReportsView extends VerticalLayout {

    private final WebsiteService websiteService;
    private final TLSInspectionService inspectionService;
    private final RiskAnalyzer riskAnalyzer;
    private final AlertService alertService;

    public ReportsView(WebsiteService websiteService,
                       TLSInspectionService inspectionService,
                       RiskAnalyzer riskAnalyzer,
                       AlertService alertService) {
        this.websiteService = websiteService;
        this.inspectionService = inspectionService;
        this.riskAnalyzer = riskAnalyzer;
        this.alertService = alertService;

        setSizeFull();
        setPadding(true);
        setSpacing(true);

        H2 header = new H2("📑 Security Reporting & Audit Exports");
        header.getStyle().set("margin-top", "0");
        Paragraph subtitle = new Paragraph("Generate downloadable, audit-ready PDF reports and comprehensive Excel workbooks detailing TLS negotiations, cryptographic certificates, risk scores, and alert history.");
        subtitle.getStyle().set("color", "#64748b");

        HorizontalLayout cards = createDownloadCards();
        Div statsPanel = createSummaryStatistics();

        add(header, subtitle, cards, statsPanel);
    }

    private HorizontalLayout createDownloadCards() {
        HorizontalLayout layout = new HorizontalLayout();
        layout.setWidthFull();
        layout.setSpacing(true);

        // PDF Report Card
        Div pdfCard = new Div();
        pdfCard.getStyle().set("background-color", "#ffffff");
        pdfCard.getStyle().set("border", "1px solid #e2e8f0");
        pdfCard.getStyle().set("border-radius", "8px");
        pdfCard.getStyle().set("padding", "1.5rem");
        pdfCard.getStyle().set("flex", "1");

        H3 pdfTitle = new H3("📄 PDF Security Audit Report");
        pdfTitle.getStyle().set("margin-top", "0");
        Paragraph pdfDesc = new Paragraph("Download a formal PDF security audit report containing full TLS handshake analysis, X.509 certificate metadata, risk scores, and remediation action items for a specific website.");

        ComboBox<Website> websiteSelect = new ComboBox<>("Select Website");
        websiteSelect.setItemLabelGenerator(Website::getDomain);
        websiteSelect.setWidthFull();
        List<Website> websites = websiteService.getAllWebsites();
        websiteSelect.setItems(websites);
        if (!websites.isEmpty()) {
            websiteSelect.setValue(websites.get(0));
        }

        Button downloadPdfBtn = new Button("Download PDF Report", VaadinIcon.DOWNLOAD.create(), e -> {
            Website site = websiteSelect.getValue();
            if (site != null) {
                UI.getCurrent().getPage().open("/api/reports/" + site.getId() + "/pdf", "_blank");
            }
        });
        downloadPdfBtn.addThemeVariants(ButtonVariant.LUMO_PRIMARY);
        downloadPdfBtn.getStyle().set("margin-top", "1rem");

        pdfCard.add(pdfTitle, pdfDesc, websiteSelect, downloadPdfBtn);

        // Excel Report Card
        Div excelCard = new Div();
        excelCard.getStyle().set("background-color", "#ffffff");
        excelCard.getStyle().set("border", "1px solid #e2e8f0");
        excelCard.getStyle().set("border-radius", "8px");
        excelCard.getStyle().set("padding", "1.5rem");
        excelCard.getStyle().set("flex", "1");

        H3 excelTitle = new H3("📊 Multi-Sheet Excel Workbook");
        excelTitle.getStyle().set("margin-top", "0");
        Paragraph excelDesc = new Paragraph("Export complete monitoring data to a formatted Microsoft Excel (.xlsx) workbook featuring 6 dedicated worksheets: Inventory, Certificate Details, TLS Inspections, Risk Scores, Findings, and Alerts.");

        Button downloadExcelBtn = new Button("Export Global Excel Workbook", VaadinIcon.TABLE.create(), e -> {
            UI.getCurrent().getPage().open("/api/reports/excel", "_blank");
        });
        downloadExcelBtn.addThemeVariants(ButtonVariant.LUMO_PRIMARY, ButtonVariant.LUMO_SUCCESS);
        downloadExcelBtn.getStyle().set("margin-top", "2.75rem");

        excelCard.add(excelTitle, excelDesc, downloadExcelBtn);

        layout.add(pdfCard, excelCard);
        return layout;
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
