package com.tlsmonitor.dashboard.view;

import com.tlsmonitor.alerts.service.AlertService;
import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.inspection.repository.CertificateDetailsRepository;
import com.tlsmonitor.inspection.repository.TLSScanResultRepository;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.repository.WebsiteRepository;
import com.tlsmonitor.risk.entity.RiskAssessment;
import com.tlsmonitor.risk.repository.RiskAssessmentRepository;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.H3;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.Icon;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import jakarta.annotation.security.PermitAll;

import java.time.format.DateTimeFormatter;
import java.util.List;

@Route(value = "", layout = MainLayout.class)
@PageTitle("Security Dashboard | Fresh TLS Monitor")
@PermitAll
public class DashboardView extends VerticalLayout {

    private final WebsiteRepository websiteRepository;
    private final TLSScanResultRepository scanRepository;
    private final CertificateDetailsRepository certRepository;
    private final RiskAssessmentRepository riskRepository;
    private final AlertService alertService;

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    public DashboardView(WebsiteRepository websiteRepository,
                         TLSScanResultRepository scanRepository,
                         CertificateDetailsRepository certRepository,
                         RiskAssessmentRepository riskRepository,
                         AlertService alertService) {
        this.websiteRepository = websiteRepository;
        this.scanRepository = scanRepository;
        this.certRepository = certRepository;
        this.riskRepository = riskRepository;
        this.alertService = alertService;

        setSpacing(true);
        setPadding(true);
        setSizeFull();

        H1 title = new H1("🛡️ Web Security & TLS Dashboard");
        title.getStyle().set("margin-bottom", "0.25rem");
        Paragraph subtitle = new Paragraph("Real-time monitoring of SSL/TLS certificates, cipher suites, expiration deadlines, and cryptographic risks.");
        subtitle.getStyle().set("color", "#64748b");

        HorizontalLayout statCards = createStatisticsRow();

        Div alertNotice = createAlertNotificationBanner();

        H3 gridTitle = new H3("Monitored Targets & Cryptographic Health");
        Grid<Website> recentGrid = createRecentGrid();

        add(title, subtitle, statCards);
        if (alertNotice != null) {
            add(alertNotice);
        }
        add(gridTitle, recentGrid);
    }

    private HorizontalLayout createStatisticsRow() {
        HorizontalLayout layout = new HorizontalLayout();
        layout.setWidthFull();
        layout.setSpacing(true);

        long totalWebsites = websiteRepository.count();
        long secureSites = riskRepository.countByRiskLevel("LOW");
        long criticalRisks = riskRepository.countByRiskLevel("CRITICAL") + riskRepository.countByRiskLevel("HIGH");
        long expiringSoon = certRepository.countExpiringSoon(30);

        layout.add(createCard("Monitored Websites", String.valueOf(totalWebsites), VaadinIcon.GLOBE, "#2563eb", "#eff6ff"));
        layout.add(createCard("Secure Endpoints", String.valueOf(secureSites), VaadinIcon.CHECK_CIRCLE, "#16a34a", "#f0fdf4"));
        layout.add(createCard("Critical & High Risks", String.valueOf(criticalRisks), VaadinIcon.EXCLAMATION_CIRCLE_O, "#dc2626", "#fef2f2"));
        layout.add(createCard("Expiring in ≤30 Days", String.valueOf(expiringSoon), VaadinIcon.CALENDAR_CLOCK, "#d97706", "#fffbeb"));

        return layout;
    }

    private Div createAlertNotificationBanner() {
        long activeAlerts = alertService.countActiveAlerts();
        if (activeAlerts == 0) {
            return null;
        }

        Div banner = new Div();
        banner.getStyle().set("background-color", "#fef2f2");
        banner.getStyle().set("border", "1px solid #f87171");
        banner.getStyle().set("border-radius", "8px");
        banner.getStyle().set("padding", "0.875rem 1.25rem");
        banner.getStyle().set("margin-top", "0.5rem");
        banner.setWidthFull();

        HorizontalLayout row = new HorizontalLayout();
        row.setDefaultVerticalComponentAlignment(FlexComponent.Alignment.CENTER);
        row.setJustifyContentMode(FlexComponent.JustifyContentMode.BETWEEN);
        row.setWidthFull();

        Span text = new Span("⚠️ Attention: " + activeAlerts + " active security alert(s) require review (expired certificates, broken chains, or weak ciphers).");
        text.getStyle().set("color", "#991b1b");
        text.getStyle().set("font-weight", "600");

        Button viewAlertsBtn = new Button("View Alerts", VaadinIcon.ARROW_RIGHT.create(), e -> UI.getCurrent().navigate("alerts"));
        viewAlertsBtn.addThemeVariants(ButtonVariant.LUMO_ERROR, ButtonVariant.LUMO_SMALL);

        row.add(text, viewAlertsBtn);
        banner.add(row);
        return banner;
    }

    private Grid<Website> createRecentGrid() {
        Grid<Website> grid = new Grid<>(Website.class, false);
        grid.setWidthFull();
        grid.setHeight("350px");

        grid.addColumn(Website::getDomain).setHeader("Domain").setAutoWidth(true).setSortable(true);
        grid.addColumn(Website::getUrl).setHeader("URL").setAutoWidth(true);

        grid.addComponentColumn(w -> {
            Span badge = new Span(w.getStatus());
            badge.getElement().getThemeList().add("badge");
            if ("ACTIVE".equalsIgnoreCase(w.getStatus())) {
                badge.getElement().getThemeList().add("success");
            } else if ("WARNING".equalsIgnoreCase(w.getStatus())) {
                badge.getElement().getThemeList().add("warning");
            } else {
                badge.getElement().getThemeList().add("error");
            }
            return badge;
        }).setHeader("Fleet Status").setWidth("120px");

        grid.addComponentColumn(w -> {
            RiskAssessment risk = riskRepository.findFirstByWebsiteIdOrderByAssessedAtDesc(w.getId()).orElse(null);
            if (risk == null) {
                return new Span("Not Assessed");
            }
            Span riskBadge = new Span(risk.getTotalScore() + "/100 (" + risk.getRiskLevel() + ")");
            riskBadge.getElement().getThemeList().add("badge");
            if ("LOW".equalsIgnoreCase(risk.getRiskLevel())) {
                riskBadge.getElement().getThemeList().add("success");
            } else if ("MEDIUM".equalsIgnoreCase(risk.getRiskLevel())) {
                riskBadge.getElement().getThemeList().add("warning");
            } else {
                riskBadge.getElement().getThemeList().add("error");
            }
            return riskBadge;
        }).setHeader("Risk Posture").setAutoWidth(true);

        grid.addColumn(w -> w.getLastScannedAt() != null
                ? w.getLastScannedAt().format(DATE_FORMATTER)
                : "Not Scanned Yet").setHeader("Last Scanned").setAutoWidth(true).setSortable(true);

        grid.addComponentColumn(w -> {
            Button pdfBtn = new Button("Audit PDF", VaadinIcon.FILE_TEXT_O.create(), e -> {
                UI.getCurrent().getPage().open("/api/reports/" + w.getId() + "/pdf", "_blank");
            });
            pdfBtn.addThemeVariants(ButtonVariant.LUMO_SMALL, ButtonVariant.LUMO_TERTIARY);

            Button inspectBtn = new Button("Inspect", VaadinIcon.SEARCH.create(), e -> {
                UI.getCurrent().navigate("inspection?websiteId=" + w.getId());
            });
            inspectBtn.addThemeVariants(ButtonVariant.LUMO_SMALL, ButtonVariant.LUMO_PRIMARY);

            HorizontalLayout actions = new HorizontalLayout(pdfBtn, inspectBtn);
            actions.setSpacing(true);
            return actions;
        }).setHeader("Quick Actions").setAutoWidth(true);

        List<Website> websites = websiteRepository.findAll();
        grid.setItems(websites);

        return grid;
    }

    private Div createCard(String title, String value, VaadinIcon iconType, String primaryColor, String bgColor) {
        Div card = new Div();
        card.getStyle().set("background-color", bgColor);
        card.getStyle().set("border", "1px solid " + primaryColor + "33");
        card.getStyle().set("border-radius", "8px");
        card.getStyle().set("padding", "1.25rem");
        card.getStyle().set("flex", "1");

        HorizontalLayout content = new HorizontalLayout();
        content.setDefaultVerticalComponentAlignment(FlexComponent.Alignment.CENTER);
        content.setJustifyContentMode(FlexComponent.JustifyContentMode.BETWEEN);

        VerticalLayout textLayout = new VerticalLayout();
        textLayout.setPadding(false);
        textLayout.setSpacing(false);

        Span label = new Span(title);
        label.getStyle().set("font-size", "0.875rem");
        label.getStyle().set("font-weight", "500");
        label.getStyle().set("color", "#475569");

        Span statValue = new Span(value);
        statValue.getStyle().set("font-size", "2rem");
        statValue.getStyle().set("font-weight", "700");
        statValue.getStyle().set("color", primaryColor);

        textLayout.add(label, statValue);

        Icon icon = iconType.create();
        icon.setSize("2.5rem");
        icon.setColor(primaryColor);

        content.add(textLayout, icon);
        card.add(content);
        return card;
    }
}
