package com.tlsmonitor.dashboard.view;

import com.vaadin.flow.router.BeforeEnterEvent;
import com.vaadin.flow.router.ErrorParameter;
import com.vaadin.flow.router.NotFoundException;
import com.vaadin.flow.router.RouteNotFoundError;
import com.vaadin.flow.server.auth.AnonymousAllowed;
import jakarta.servlet.http.HttpServletResponse;

@AnonymousAllowed
public class CustomRouteNotFoundError extends RouteNotFoundError {

    @Override
    public int setErrorParameter(BeforeEnterEvent event, ErrorParameter<NotFoundException> parameter) {
        // Automatically redirect unknown routes (e.g. tracking extensions, invalid URLs) to the dashboard
        event.forwardTo("");
        return HttpServletResponse.SC_OK;
    }
}
