package com.tlsmonitor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class TLSMonitorApplication {

    public static void main(String[] args) {
        SpringApplication.run(TLSMonitorApplication.class, args);
    }
}
