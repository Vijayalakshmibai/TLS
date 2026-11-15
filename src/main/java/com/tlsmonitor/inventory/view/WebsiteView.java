package com.tlsmonitor.inventory.view;

import com.tlsmonitor.dashboard.view.MainLayout;
import com.tlsmonitor.inventory.entity.Website;
import com.tlsmonitor.inventory.service.WebsiteService;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.dialog.Dialog;
import com.vaadin.flow.component.formlayout.FormLayout;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.notification.NotificationVariant;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.select.Select;
import com.vaadin.flow.component.textfield.IntegerField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.data.value.ValueChangeMode;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import jakarta.annotation.security.PermitAll;

import java.time.format.DateTimeFormatter;
import java.util.List;

@Route(value = "websites", layout = MainLayout.class)
@PageTitle("Website Inventory | Fresh TLS Monitor")
@PermitAll
public class WebsiteView extends VerticalLayout {

    private final WebsiteService websiteService;
    private final Grid<Website> grid = new Grid<>(Website.class, false);
    private final TextField filterText = new TextField();
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    public WebsiteView(WebsiteService websiteService) {
        this.websiteService = websiteService;
        setSizeFull();
        setPadding(true);
        setSpacing(true);

        H2 header = new H2("🌐 Website & Certificate Inventory");
        header.getStyle().set("margin-top", "0");

        HorizontalLayout toolbar = createToolbar();
        configureGrid();

        add(header, toolbar, grid);
        updateList();
    }

    private HorizontalLayout createToolbar() {
        filterText.setPlaceholder("Filter by domain or description...");
        filterText.setClearButtonVisible(true);
        filterText.setValueChangeMode(ValueChangeMode.LAZY);
        filterText.addValueChangeListener(e -> updateList());
        filterText.setWidth("350px");

        Button addWebsiteBtn = new Button("Add Website", VaadinIcon.PLUS.create(), e -> openAddDialog());
        addWebsiteBtn.addThemeVariants(ButtonVariant.LUMO_PRIMARY);

        HorizontalLayout toolbar = new HorizontalLayout(filterText, addWebsiteBtn);
        toolbar.setWidthFull();
        toolbar.setDefaultVerticalComponentAlignment(FlexComponent.Alignment.CENTER);
        return toolbar;
    }

    private void configureGrid() {
        grid.setSizeFull();

        grid.addColumn(Website::getDomain).setHeader("Domain").setSortable(true).setAutoWidth(true);
        grid.addColumn(Website::getUrl).setHeader("URL").setAutoWidth(true);
        grid.addColumn(Website::getPort).setHeader("Port").setWidth("90px");

        grid.addComponentColumn(website -> {
            Span badge = new Span(website.getStatus());
            badge.getElement().getThemeList().add("badge");
            if ("ACTIVE".equalsIgnoreCase(website.getStatus())) {
                badge.getElement().getThemeList().add("success");
            } else if ("WARNING".equalsIgnoreCase(website.getStatus())) {
                badge.getElement().getThemeList().add("warning");
            } else {
                badge.getElement().getThemeList().add("error");
            }
            return badge;
        }).setHeader("Status").setWidth("120px");

        grid.addColumn(website -> website.getLastScannedAt() != null
                ? website.getLastScannedAt().format(DATE_FORMATTER)
                : "Not Scanned Yet").setHeader("Last Scanned").setSortable(true).setAutoWidth(true);

        grid.addComponentColumn(website -> {
            Button scanBtn = new Button("Scan", VaadinIcon.SEARCH.create(), e -> {
                Notification.show("Starting inspection for " + website.getDomain(), 3000, Notification.Position.TOP_CENTER)
                        .addThemeVariants(NotificationVariant.LUMO_PRIMARY);
                UI.getCurrent().navigate("inspection?websiteId=" + website.getId());
            });
            scanBtn.addThemeVariants(ButtonVariant.LUMO_SMALL, ButtonVariant.LUMO_SUCCESS);

            Button editBtn = new Button(VaadinIcon.EDIT.create(), e -> openEditDialog(website));
            editBtn.addThemeVariants(ButtonVariant.LUMO_SMALL, ButtonVariant.LUMO_TERTIARY);

            Button deleteBtn = new Button(VaadinIcon.TRASH.create(), e -> openDeleteConfirmDialog(website));
            deleteBtn.addThemeVariants(ButtonVariant.LUMO_SMALL, ButtonVariant.LUMO_ERROR, ButtonVariant.LUMO_TERTIARY);

            HorizontalLayout actions = new HorizontalLayout(scanBtn, editBtn, deleteBtn);
            actions.setSpacing(true);
            return actions;
        }).setHeader("Actions").setAutoWidth(true);
    }

    private void updateList() {
        List<Website> websites = websiteService.getAllWebsites();
        String filter = filterText.getValue();
        if (filter != null && !filter.trim().isEmpty()) {
            String lower = filter.trim().toLowerCase();
            websites = websites.stream()
                    .filter(w -> (w.getDomain() != null && w.getDomain().toLowerCase().contains(lower)) ||
                            (w.getDescription() != null && w.getDescription().toLowerCase().contains(lower)))
                    .toList();
        }
        grid.setItems(websites);
    }

    private void openAddDialog() {
        Dialog dialog = new Dialog();
        dialog.setHeaderTitle("Add Website for Monitoring");

        TextField domainField = new TextField("Domain or HTTPS URL");
        domainField.setPlaceholder("e.g. google.com or https://github.com");
        domainField.setRequired(true);
        domainField.setWidthFull();

        IntegerField portField = new IntegerField("HTTPS Port");
        portField.setValue(443);
        portField.setMin(1);
        portField.setMax(65535);

        TextField descField = new TextField("Description");
        descField.setPlaceholder("e.g. Production Gateway");
        descField.setWidthFull();

        TextField emailField = new TextField("Alert Contact Email");
        emailField.setPlaceholder("admin@example.com");
        emailField.setWidthFull();

        FormLayout form = new FormLayout(domainField, portField, descField, emailField);
        dialog.add(form);

        Button saveBtn = new Button("Register Website", e -> {
            try {
                Website site = new Website();
                site.setDomain(domainField.getValue());
                if (portField.getValue() != null) {
                    site.setPort(portField.getValue());
                }
                site.setDescription(descField.getValue());
                site.setContactEmail(emailField.getValue());
                site.setStatus("ACTIVE");

                websiteService.addWebsite(site);
                Notification.show("Website registered successfully!", 3000, Notification.Position.TOP_CENTER)
                        .addThemeVariants(NotificationVariant.LUMO_SUCCESS);
                dialog.close();
                updateList();
            } catch (Exception ex) {
                Notification.show(ex.getMessage(), 5000, Notification.Position.TOP_CENTER)
                        .addThemeVariants(NotificationVariant.LUMO_ERROR);
            }
        });
        saveBtn.addThemeVariants(ButtonVariant.LUMO_PRIMARY);

        Button cancelBtn = new Button("Cancel", e -> dialog.close());
        dialog.getFooter().add(cancelBtn, saveBtn);
        dialog.open();
    }

    private void openEditDialog(Website website) {
        Dialog dialog = new Dialog();
        dialog.setHeaderTitle("Edit " + website.getDomain());

        TextField descField = new TextField("Description");
        descField.setValue(website.getDescription() != null ? website.getDescription() : "");
        descField.setWidthFull();

        TextField emailField = new TextField("Alert Contact Email");
        emailField.setValue(website.getContactEmail() != null ? website.getContactEmail() : "");
        emailField.setWidthFull();

        Select<String> statusSelect = new Select<>();
        statusSelect.setLabel("Status");
        statusSelect.setItems("ACTIVE", "INACTIVE", "WARNING");
        statusSelect.setValue(website.getStatus());

        FormLayout form = new FormLayout(descField, emailField, statusSelect);
        dialog.add(form);

        Button saveBtn = new Button("Save Changes", e -> {
            try {
                website.setDescription(descField.getValue());
                website.setContactEmail(emailField.getValue());
                website.setStatus(statusSelect.getValue());
                websiteService.updateWebsite(website.getId(), website);
                Notification.show("Website updated successfully!", 3000, Notification.Position.TOP_CENTER)
                        .addThemeVariants(NotificationVariant.LUMO_SUCCESS);
                dialog.close();
                updateList();
            } catch (Exception ex) {
                Notification.show(ex.getMessage(), 5000, Notification.Position.TOP_CENTER)
                        .addThemeVariants(NotificationVariant.LUMO_ERROR);
            }
        });
        saveBtn.addThemeVariants(ButtonVariant.LUMO_PRIMARY);

        Button cancelBtn = new Button("Cancel", e -> dialog.close());
        dialog.getFooter().add(cancelBtn, saveBtn);
        dialog.open();
    }

    private void openDeleteConfirmDialog(Website website) {
        Dialog dialog = new Dialog();
        dialog.setHeaderTitle("Confirm Deletion");
        dialog.add(new Span("Are you sure you want to delete '" + website.getDomain() + "' from monitoring inventory?"));

        Button deleteBtn = new Button("Delete", e -> {
            websiteService.deleteWebsite(website.getId());
            Notification.show("Website removed from inventory.", 3000, Notification.Position.TOP_CENTER);
            dialog.close();
            updateList();
        });
        deleteBtn.addThemeVariants(ButtonVariant.LUMO_PRIMARY, ButtonVariant.LUMO_ERROR);

        Button cancelBtn = new Button("Cancel", e -> dialog.close());
        dialog.getFooter().add(cancelBtn, deleteBtn);
        dialog.open();
    }
}
