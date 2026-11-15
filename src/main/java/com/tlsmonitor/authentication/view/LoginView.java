package com.tlsmonitor.authentication.view;

import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.login.LoginForm;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.BeforeEnterObserver;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.auth.AnonymousAllowed;

@Route("login")
@PageTitle("Login | Fresh TLS Monitor")
@AnonymousAllowed
public class LoginView extends VerticalLayout implements BeforeEnterObserver {

    private final LoginForm loginForm = new LoginForm();

    public LoginView() {
        addClassName("login-view");
        setSizeFull();
        setAlignItems(Alignment.CENTER);
        setJustifyContentMode(JustifyContentMode.CENTER);

        loginForm.setAction("login");

        H1 heading = new H1("🔐 Fresh TLS Monitor");
        heading.getStyle().set("margin-bottom", "0");
        heading.getStyle().set("color", "#1a365d");

        Paragraph description = new Paragraph("Web Security & Certificate Analysis Platform");
        description.getStyle().set("color", "#4a5568");
        description.getStyle().set("margin-top", "4px");

        Paragraph hint = new Paragraph("Default credentials: admin / admin123");
        hint.getStyle().set("font-size", "0.85rem");
        hint.getStyle().set("color", "#718096");

        add(heading, description, loginForm, hint);
    }

    @Override
    public void beforeEnter(BeforeEnterEvent beforeEnterEvent) {
        if (beforeEnterEvent.getLocation()
                .getQueryParameters()
                .getParameters()
                .containsKey("error")) {
            loginForm.setError(true);
        }
    }
}
