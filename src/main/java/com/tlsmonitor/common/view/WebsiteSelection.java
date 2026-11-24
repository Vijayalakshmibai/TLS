package com.tlsmonitor.common.view;

import com.tlsmonitor.inventory.entity.Website;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.router.BeforeEnterEvent;

import java.util.List;
import java.util.Optional;

/**
 * Shared website-selection state for the Inspection / Risk Analysis / Reports pages so the
 * target website survives navigation between them.
 *
 * Priority:
 *   1. explicit {@code ?websiteId=<id>} query parameter (shareable / deep-linkable)
 *   2. last selection remembered in the Vaadin session (drawer navigation)
 *   3. first website in the inventory
 */
public final class WebsiteSelection {

    private static final String SESSION_KEY = "freshTls.selectedWebsiteId";

    private WebsiteSelection() {
    }

    /**
     * Resolves which website should be selected for a page load and remembers it.
     */
    public static Optional<Long> resolve(BeforeEnterEvent event, List<Website> websites) {
        Optional<Long> fromParam = websiteIdFromQueryParam(event, websites);
        if (fromParam.isPresent()) {
            remember(fromParam.get());
            return fromParam;
        }
        Optional<Long> fromSession = websiteIdFromSession(websites);
        if (fromSession.isPresent()) {
            return fromSession;
        }
        return websites.isEmpty() ? Optional.empty() : Optional.of(websites.get(0).getId());
    }

    /** Remembers the given website as the current selection for the rest of the session. */
    public static void remember(Long websiteId) {
        UI ui = UI.getCurrent();
        if (websiteId != null && ui != null) {
            ui.getSession().setAttribute(SESSION_KEY, websiteId);
        }
    }

    private static Optional<Long> websiteIdFromQueryParam(BeforeEnterEvent event, List<Website> websites) {
        List<String> params = event.getLocation().getQueryParameters().getParameters().get("websiteId");
        if (params == null || params.isEmpty()) {
            return Optional.empty();
        }
        try {
            long id = Long.parseLong(params.get(0).trim());
            return websites.stream().anyMatch(w -> w.getId() == id) ? Optional.of(id) : Optional.empty();
        } catch (NumberFormatException ignored) {
            return Optional.empty();
        }
    }

    private static Optional<Long> websiteIdFromSession(List<Website> websites) {
        UI ui = UI.getCurrent();
        if (ui == null) {
            return Optional.empty();
        }
        Object stored = ui.getSession().getAttribute(SESSION_KEY);
        Long id = null;
        if (stored instanceof Number number) {
            id = number.longValue();
        }
        if (id == null) {
            return Optional.empty();
        }
        Long finalId = id;
        return websites.stream().anyMatch(w -> w.getId().equals(finalId)) ? Optional.of(finalId) : Optional.empty();
    }
}
