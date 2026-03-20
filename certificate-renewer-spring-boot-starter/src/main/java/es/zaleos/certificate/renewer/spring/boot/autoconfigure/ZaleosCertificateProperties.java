package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Public configuration model for the Zaleos certificate starter.
 */
@ConfigurationProperties("zaleos.certificate")
public class ZaleosCertificateProperties {

    private boolean enabled = true;
    private final Bootstrap bootstrap = new Bootstrap();
    private final Maintenance maintenance = new Maintenance();
    private final Output output = new Output();
    private final Map<String, Target> targets = new LinkedHashMap<>();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Bootstrap getBootstrap() {
        return bootstrap;
    }

    public Maintenance getMaintenance() {
        return maintenance;
    }

    public Output getOutput() {
        return output;
    }

    public Map<String, Target> getTargets() {
        return targets;
    }

    public static class Bootstrap {
        private boolean enabled = true;
        private boolean onlyIfMissing = true;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isOnlyIfMissing() {
            return onlyIfMissing;
        }

        public void setOnlyIfMissing(boolean onlyIfMissing) {
            this.onlyIfMissing = onlyIfMissing;
        }
    }

    public static class Maintenance {
        private boolean allowPost;
        private String endpointPath = "/internal/certificates/import-upload";
        private String folderEndpointPath = "/internal/certificates/import-from-folder";

        public boolean isAllowPost() {
            return allowPost;
        }

        public void setAllowPost(boolean allowPost) {
            this.allowPost = allowPost;
        }

        public String getEndpointPath() {
            return endpointPath;
        }

        public void setEndpointPath(String endpointPath) {
            this.endpointPath = endpointPath;
        }

        public String getFolderEndpointPath() {
            return folderEndpointPath;
        }

        public void setFolderEndpointPath(String folderEndpointPath) {
            this.folderEndpointPath = folderEndpointPath;
        }
    }

    public static class Output {
        private String privateKeyPassword;
        private boolean writeUnencryptedPrivateKey;

        public String getPrivateKeyPassword() {
            return privateKeyPassword;
        }

        public void setPrivateKeyPassword(String privateKeyPassword) {
            this.privateKeyPassword = privateKeyPassword;
        }

        public boolean isWriteUnencryptedPrivateKey() {
            return writeUnencryptedPrivateKey;
        }

        public void setWriteUnencryptedPrivateKey(boolean writeUnencryptedPrivateKey) {
            this.writeUnencryptedPrivateKey = writeUnencryptedPrivateKey;
        }
    }

    public static class Target {
        private String type = "filesystem";
        private String outputDir;
        private String certificatePath;
        private String chainPath;
        private String fullChainPath;
        private String privateKeyPath;
        private boolean activate = true;
        private boolean bootstrapEnabled;

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getOutputDir() {
            return outputDir;
        }

        public void setOutputDir(String outputDir) {
            this.outputDir = outputDir;
        }

        public String getCertificatePath() {
            return certificatePath;
        }

        public void setCertificatePath(String certificatePath) {
            this.certificatePath = certificatePath;
        }

        public String getChainPath() {
            return chainPath;
        }

        public void setChainPath(String chainPath) {
            this.chainPath = chainPath;
        }

        public String getFullChainPath() {
            return fullChainPath;
        }

        public void setFullChainPath(String fullChainPath) {
            this.fullChainPath = fullChainPath;
        }

        public String getPrivateKeyPath() {
            return privateKeyPath;
        }

        public void setPrivateKeyPath(String privateKeyPath) {
            this.privateKeyPath = privateKeyPath;
        }

        public boolean isActivate() {
            return activate;
        }

        public void setActivate(boolean activate) {
            this.activate = activate;
        }

        public boolean isBootstrapEnabled() {
            return bootstrapEnabled;
        }

        public void setBootstrapEnabled(boolean bootstrapEnabled) {
            this.bootstrapEnabled = bootstrapEnabled;
        }
    }
}
