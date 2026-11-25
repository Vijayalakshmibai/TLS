package com.tlsmonitor.alerts.view;

import com.tlsmonitor.alerts.entity.Alert;
import com.tlsmonitor.alerts.service.AlertService;
import com.tlsmonitor.dashboard.view.MainLayout;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.select.Select;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import jakarta.annotation.security.PermitAll;

import java.time.format.DateTimeFormatter;
import java.util.List;

@Route(value = "alerts", layout = MainLayout.class)
@PageTitle("Security Alerts | Fresh TLS Monitor")
@PermitAll
public class AlertsView extends VerticalLayout implements BeforeEnterObserver {

    private final AlertService alertService;
    private final Grid<Alert> grid = new Grid<>(Alert.class, false);
    private final Select<String> statusFilter = new Select<>();
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public AlertsView(AlertService alertService) {
        this.alertService = alertService;

        setSizeFull();
        setPadding(true);
        setSpacing(true);

        H2 header = new H2("🔔 Security Notifications & Alert History");
        header.getStyle().set("margin-top", "0");
        Paragraph subtitle = new Paragraph("Track certificate expiration warnings, critical configuration findings, and hostname mismatches with automated deduplication and acknowledgment workflow.");
        subtitle.getStyle().set("color", "#64748b");

        HorizontalLayout toolbar = createToolbar();
        configureGrid();

        add(header, subtitle, toolbar, grid);
        updateAlertsList();
    }

    @Override
    public void beforeEnter(BeforeEnterEvent event) {
        updateAlertsList();
    }

    private HorizontalLayout createToolbar() {
        statusFilter.setLabel("Filter by Alert Status");
        statusFilter.setItems("ACTIVE", "ALL", "PENDING", "SENT", "ACKNOWLEDGED", "RESOLVED");
        statusFilter.setValue("ACTIVE");
        statusFilter.setWidth("220px");
        statusFilter.addValueChangeListener(e -> updateAlertsList());

        Button refreshBtn = new Button("Refresh Alerts", VaadinIcon.REFRESH.create(), e -> updateAlertsList());
        refreshBtn.addThemeVariants(ButtonVariant.LUMO_TERTIARY);

        HorizontalLayout toolbar = new HorizontalLayout(statusFilter, refreshBtn);
        toolbar.setDefaultVerticalComponentAlignment(FlexComponent.Alignment.END);
        return toolbar;
    }

    private void configureGrid() {
        grid.setSizeFull();

        grid.addComponentColumn(a -> {
            Span badge = new Span(a.getSeverity());
            badge.getStyle().set("padding", "0.2rem 0.5rem");
            badge.getStyle().set("border-radius", "4px");
            badge.getStyle().set("font-weight", "600");
            badge.getStyle().set("font-size", "0.8rem");

            switch (a.getSeverity().toUpperCase()) {
                case "CRITICAL" -> {
                    badge.getStyle().set("color", "#991b1b");
                    badge.getStyle().set("background-color", "#fee2e2");
                }
                case "HIGH" -> {
                    badge.getStyle().set("color", "#c2410c");
                    badge.getStyle().set("background-color", "#ffedd5");
                }
                default -> {
                    badge.getStyle().set("color", "#15803d");
                    badge.getStyle().set("background-color", "#dcfce7");
                }
            }
            return badge;
        }).setHeader("Severity").setWidth("110px");

        grid.addColumn(Alert::getDomain).setHeader("Target Domain").setAutoWidth(true).setSortable(true);
        grid.addColumn(Alert::getAlertType).setHeader("Alert Type").setAutoWidth(true);
        grid.addColumn(Alert::getMessage).setHeader("Alert Message").setAutoWidth(true);

        grid.addComponentColumn(a -> {
            Span statusBadge = new Span(a.getStatus());
            statusBadge.getElement().getThemeList().add("badge");
            if ("RESOLVED".equalsIgnoreCase(a.getStatus())) {
                statusBadge.getElement().getThemeList().add("success");
            } else if ("ACKNOWLEDGED".equalsIgnoreCase(a.getStatus())) {
                statusBadge.getElement().getThemeList().add("contrast");
            } else {
                statusBadge.getElement().getThemeList().add("warning");
            }
            return statusBadge;
        }).setHeader("Status").setWidth("140px");

        grid.addColumn(a -> a.getCreatedAt() != null ? a.getCreatedAt().format(DATE_FORMATTER) : "").setHeader("Created At").setAutoWidth(true);

        grid.addColumn(a -> {
            if (a.getReportDeliveryStatus() == null) {
                return "Not Sent";
            }
            String ts = a.getReportSentAt() != null ? " (" + a.getReportSentAt().format(DATE_FORMATTER) + ")" : "";
            return a.getReportDeliveryStatus() + ts;
        }).setHeader("Report Delivery").setAutoWidth(true);

        grid.addComponentColumn(alert -> {
            Button sendReportBtn = new Button("Send PDF Report", VaadinIcon.ENVELOPE.create());
            sendReportBtn.addThemeVariants(ButtonVariant.LUMO_SMALL, ButtonVariant.LUMO_PRIMARY);
            sendReportBtn.setDisableOnClick(true);
            sendReportBtn.addClickListener(e -> {
                sendReportBtn.setText("Sending...");
                try {
                    boolean sent = alertService.sendAlertPdfReport(alert.getId());
                    if (sent) {
                        Notification.show("PDF security report sent successfully via Gmail SMTP.", 4000, Notification.Position.TOP_CENTER)
                                .addThemeVariants(NotificationVariant.LUMO_SUCCESS);
                    } else {
                        Notification.show("Failed to send PDF report. Verify MAIL_USERNAME and MAIL_APP_PASSWORD.", 5000, Notification.Position.TOP_CENTER)
                                .addThemeVariants(NotificationVariant.LUMO_ERROR);
                    }
                } catch (Exception ex) {
                    Notification.show("Error sending PDF report: " + ex.getMessage(), 5000, Notification.Position.TOP_CENTER)
                            .addThemeVariants(NotificationVariant.LUMO_ERROR);
                } finally {
                    sendReportBtn.setText("Send PDF Report");
                    sendReportBtn.setEnabled(true);
                    updateAlertsList();
                }
            });

            HorizontalLayout actions = new HorizontalLayout(sendReportBtn);
            actions.setSpacing(true);
            return actions;
        }).setHeader("Actions").setAutoWidth(true);
    }

    private void updateAlertsList() {
        List<Alert> alerts = alertService.getAllAlerts();
        String filter = statusFilter.getValue();
        if ("ACTIVE".equalsIgnoreCase(filter)) {
            alerts = alerts.stream()
                    .filter(a -> "PENDING".equalsIgnoreCase(a.getStatus()) || "SENT".equalsIgnoreCase(a.getStatus()))
                    .toList();
        } else if (filter != null && !"ALL".equalsIgnoreCase(filter)) {
            alerts = alerts.stream().filter(a -> a.getStatus().equalsIgnoreCase(filter)).toList();
        }
        grid.setItems(alerts);
    }
}
