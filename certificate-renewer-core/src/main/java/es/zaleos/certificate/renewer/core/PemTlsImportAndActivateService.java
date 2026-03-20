package es.zaleos.certificate.renewer.core;

import java.nio.file.Path;

/**
 * High-level facade that imports TLS material and writes it as PEM output.
 */
public class PemTlsImportAndActivateService {

    private final PemTlsMaterialImporter importer;
    private final PemTlsMaterialWriter writer;

    public PemTlsImportAndActivateService() {
        this(new PemTlsMaterialImporter(), new PemTlsMaterialWriter());
    }

    public PemTlsImportAndActivateService(PemTlsMaterialImporter importer, PemTlsMaterialWriter writer) {
        this.importer = importer;
        this.writer = writer;
    }

    public PemActivationResult importAndActivate(
            Path sourcePath,
            Path externalPrivateKeyPath,
            char[] sourcePassword,
            PemTlsTargetPaths targetPaths,
            char[] outputPrivateKeyPassword,
            boolean allowUnencryptedPrivateKey
    ) throws Exception {
        PemTlsMaterial material = importer.importFrom(sourcePath, externalPrivateKeyPath, sourcePassword);
        return writer.writeAtomically(material, targetPaths, outputPrivateKeyPassword, allowUnencryptedPrivateKey);
    }
}
