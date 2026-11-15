package com.tlsmonitor.dashboard.view;

import com.tlsmonitor.authentication.security.SecurityService;
import com.vaadin.flow.component.applayout.AppLayout;
import com.vaadin.flow.component.applayout.DrawerToggle;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.sidenav.SideNav;
import com.vaadin.flow.component.sidenav.SideNavItem;

public class MainLayout extends AppLayout {

    private final SecurityService securityService;

    public MainLayout(SecurityService securityService) {
        this.securityService = securityService;
        createHeader();
        createDrawer();
    }

    private void createHeader() {
        H2 logo = new H2("Fresh TLS Monitor");
        logo.addClassNames("text-l", "m-m");
        logo.getStyle().set("font-size", "1.25rem");
        logo.getStyle().set("color", "#1e3a8a");

        String username = securityService.getAuthenticatedUser()
                .map(user -> user.getUsername())
                .orElse("Admin");

        Span userBadge = new Span("👤 " + username);
        userBadge.getStyle().set("font-weight", "600");
        userBadge.getStyle().set("color", "#4b5563");
        userBadge.getStyle().set("margin-right", "1rem");

        Button logoutBtn = new Button("Logout", VaadinIcon.SIGN_OUT.create(), e -> securityService.logout());
        logoutBtn.addThemeVariants(ButtonVariant.LUMO_SMALL, ButtonVariant.LUMO_TERTIARY);

        HorizontalLayout header = new HorizontalLayout(new DrawerToggle(), logo, userBadge, logoutBtn);
        header.setDefaultVerticalComponentAlignment(FlexComponent.Alignment.CENTER);
        header.expand(logo);
        header.setWidthFull();
        header.addClassNames("py-0", "px-m");

        addToNavbar(header);
    }

    private void createDrawer() {
        SideNav nav = new SideNav();
        nav.addItem(new SideNavItem("Dashboard", DashboardView.class, VaadinIcon.DASHBOARD.create()));
        nav.addItem(new SideNavItem("Website Inventory", "websites", VaadinIcon.GLOBE.create()));
        nav.addItem(new SideNavItem("TLS Inspection", "inspection", VaadinIcon.SHIELD.create()));
        nav.addItem(new SideNavItem("Risk Analysis", "risks", VaadinIcon.WARNING.create()));
        nav.addItem(new SideNavItem("Reports", "reports", VaadinIcon.FILE_TEXT.create()));
        nav.addItem(new SideNavItem("Alerts", "alerts", VaadinIcon.BELL.create()));

        VerticalLayout layout = new VerticalLayout(nav);
        layout.setSizeFull();
        addToDrawer(layout);
    }
}
