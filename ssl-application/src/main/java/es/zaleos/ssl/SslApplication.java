package es.zaleos.ssl;

import es.zaleos.ssl.cli.SetupConfigurator;
import es.zaleos.ssl.cli.StandaloneInstallationCheck;
import es.zaleos.ssl.cli.TlsMaterialImporter;
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

    private static final String SETUP_COMMAND = "--setup";
    private static final String CHECK_INSTALLATION_COMMAND = "--check-installation";
    private static final String IMPORT_TLS_MATERIAL_COMMAND = "--import-tls-material";
    private static final String LEGACY_RENEW_CERTIFICATE_COMMAND = "--renew-certificate";

    /**
     * Starts the application and dispatches optional CLI tasks.
     *
     * @param args runtime arguments
     */
    public static void main(String[] args) {
        List<String> argsList = Arrays.asList(args);

        // Handle setup mode separately to avoid unnecessary Spring context initialization
        if (argsList.contains(SETUP_COMMAND)) {
            new SetupConfigurator().execute();
            System.exit(0);
        }
        if (argsList.contains(CHECK_INSTALLATION_COMMAND)) {
            int exitCode = new StandaloneInstallationCheck().execute(args);
            System.exit(exitCode);
        }

        // For CLI tasks, we disable web environment to speed up execution and reduce resource usage
        SpringApplication app = new SpringApplication(SslApplication.class);
        boolean isCliMode = argsList.contains(IMPORT_TLS_MATERIAL_COMMAND)
                || argsList.contains(LEGACY_RENEW_CERTIFICATE_COMMAND);
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
            if (argsList.contains(IMPORT_TLS_MATERIAL_COMMAND)
                    || argsList.contains(LEGACY_RENEW_CERTIFICATE_COMMAND)) {
                context.getBean(TlsMaterialImporter.class).execute();
            }
            System.exit(0);
        } catch (Exception exception) {
            System.err.println("[FATAL] CLI execution failed: " + exception.getMessage());
            System.exit(1);
        }
    }
}
