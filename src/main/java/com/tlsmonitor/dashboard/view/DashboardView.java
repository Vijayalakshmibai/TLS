package com.tlsmonitor.dashboard.view;

import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.auth.AnonymousAllowed;

@Route("")
@PageTitle("Dashboard | Fresh TLS Monitor")
@AnonymousAllowed
public class DashboardView extends VerticalLayout {

    public DashboardView() {
        setSpacing(true);
        setPadding(true);
        addClassName("dashboard-view");

        H1 title = new H1("Fresh TLS Certificate Monitoring & Web Security Analysis Tool");
        Paragraph subtitle = new Paragraph("Java Full-Stack Security Monitoring Platform running on Spring Boot, Vaadin Flow, and PostgreSQL.");

        add(title, subtitle);
    }
}
