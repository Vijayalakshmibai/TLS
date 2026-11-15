package com.tlsmonitor.dashboard.view;

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

@Route(value = "", layout = MainLayout.class)
@PageTitle("Security Dashboard | Fresh TLS Monitor")
@PermitAll
public class DashboardView extends VerticalLayout {

    public DashboardView() {
        setSpacing(true);
        setPadding(true);
        setSizeFull();

        H1 title = new H1("🛡️ Web Security & TLS Dashboard");
        title.getStyle().set("margin-bottom", "0.25rem");
        Paragraph subtitle = new Paragraph("Real-time monitoring of SSL/TLS certificates, cipher suites, expiration deadlines, and cryptographic risks.");
        subtitle.getStyle().set("color", "#64748b");

        HorizontalLayout statCards = createStatisticsRow();

        Div infoBox = new Div();
        infoBox.getStyle().set("background-color", "#f8fafc");
        infoBox.getStyle().set("border", "1px solid #e2e8f0");
        infoBox.getStyle().set("border-radius", "8px");
        infoBox.getStyle().set("padding", "1.5rem");
        infoBox.getStyle().set("margin-top", "1.5rem");
        infoBox.setWidthFull();

        H3 infoTitle = new H3("Centralized TLS Monitoring Architecture");
        Paragraph infoText = new Paragraph("This platform uses Java JSSE and X.509 Cryptography APIs to establish secure TLS handshakes, extract server certificates, inspect cipher suites, and compute risk levels directly in Java without external scanning APIs. Navigate via the sidebar to manage websites or perform on-demand inspections.");
        infoBox.add(infoTitle, infoText);

        add(title, subtitle, statCards, infoBox);
    }

    private HorizontalLayout createStatisticsRow() {
        HorizontalLayout layout = new HorizontalLayout();
        layout.setWidthFull();
        layout.setSpacing(true);

        layout.add(createCard("Monitored Websites", "0", VaadinIcon.GLOBE, "#2563eb", "#eff6ff"));
        layout.add(createCard("Secure Certificates", "0", VaadinIcon.CHECK_CIRCLE, "#16a34a", "#f0fdf4"));
        layout.add(createCard("Critical Risks", "0", VaadinIcon.EXCLAMATION_CIRCLE_O, "#dc2626", "#fef2f2"));
        layout.add(createCard("Expiring in 30 Days", "0", VaadinIcon.CALENDAR_CLOCK, "#d97706", "#fffbeb"));

        return layout;
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
