package com.tlsmonitor.common.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;

@Controller
@RequestMapping("/hybridaction")
public class HybridActionFallbackController {

    @GetMapping("/**")
    public String handleHybridAction(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String accept = request.getHeader("Accept");
        if (accept != null && accept.contains("text/html")) {
            // If opened in browser address bar, redirect gracefully to Dashboard
            return "redirect:/";
        }

        // If invoked as a background script/beacon, respond with 200 OK
        response.setContentType("application/javascript;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write("// ok");
        return null;
    }
}
