package com.example.ssl;

import com.example.ssl.cli.CertificateRenewer;
import com.example.ssl.cli.CheckInstallation;
import com.example.ssl.cli.SetupConfigurator;
import java.util.Arrays;
import java.util.List;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * Application entry point for the HTTPS-only sample.
 */
@SpringBootApplication
public class SslApplication {

    /**
     * Starts the application and dispatches optional CLI tasks.
     *
     * @param args runtime arguments
     */
    public static void main(String[] args) {
        List<String> argsList = Arrays.asList(args);

        // Handle setup mode separately to avoid unnecessary Spring context initialization
        if (argsList.contains("--setup")) {
            new SetupConfigurator().execute();
            System.exit(0);
        }

        // For CLI tasks, we disable web environment to speed up execution and reduce resource usage
        SpringApplication app = new SpringApplication(SslApplication.class);
        boolean isCliMode = argsList.contains("--check-installation") || argsList.contains("--renew-certificate");
        if (isCliMode) {
            app.setWebApplicationType(WebApplicationType.NONE);
        }

        ConfigurableApplicationContext context = null;
        try {
            context = app.run(args);
            if (isCliMode) {
                runCliTask(context, argsList);
            }
        } catch (Exception exception) {
            System.err.println("[FATAL] Application startup failed: " + exception.getMessage());
            System.exit(1);
        }
    }

    /**
     * Executes the requested CLI task using Spring-managed beans.
     *
     * @param context active Spring context
     * @param argsList parsed arguments
     */
    private static void runCliTask(ConfigurableApplicationContext context, List<String> argsList) {
        try {
            if (argsList.contains("--check-installation")) {
                context.getBean(CheckInstallation.class).execute();
            } else if (argsList.contains("--renew-certificate")) {
                context.getBean(CertificateRenewer.class).execute();
            }
            System.exit(0);
        } catch (Exception exception) {
            System.err.println("[FATAL] CLI execution failed: " + exception.getMessage());
            System.exit(1);
        }
    }
}
