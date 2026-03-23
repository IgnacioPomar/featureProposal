package es.zaleos.certificate.renewer.core;

import java.nio.file.Path;

/**
 * High-level facade that imports TLS material and writes it as PEM output.
 */
public class PemTlsImportAndActivateService {

    private final PemTlsMaterialImporter importer;
    private final PemTlsMaterialWriter writer;
    private final PemTlsCurrentMaterialLoader currentMaterialLoader;
    private final PemTlsMaterialValidator validator;

    public PemTlsImportAndActivateService() {
        this(new PemTlsMaterialImporter(), new PemTlsMaterialWriter(),
                new PemTlsCurrentMaterialLoader(), new PemTlsMaterialValidator());
    }

    public PemTlsImportAndActivateService(
            PemTlsMaterialImporter importer,
            PemTlsMaterialWriter writer,
            PemTlsCurrentMaterialLoader currentMaterialLoader,
            PemTlsMaterialValidator validator
    ) {
        this.importer = importer;
        this.writer = writer;
        this.currentMaterialLoader = currentMaterialLoader;
        this.validator = validator;
    }

    public PemActivationResult importAndActivate(
            Path sourcePath,
            Path externalPrivateKeyPath,
            char[] sourcePassword,
            PemTlsTargetPaths targetPaths,
            char[] outputPrivateKeyPassword,
            boolean allowUnencryptedPrivateKey
    ) throws Exception {
        return importAndActivate(
                sourcePath,
                externalPrivateKeyPath,
                sourcePassword,
                targetPaths,
                outputPrivateKeyPassword,
                allowUnencryptedPrivateKey,
                null
        );
    }

    public PemActivationResult importAndActivate(
            Path sourcePath,
            Path externalPrivateKeyPath,
            char[] sourcePassword,
            PemTlsTargetPaths targetPaths,
            char[] outputPrivateKeyPassword,
            boolean allowUnencryptedPrivateKey,
            PemTlsValidationPolicy validationPolicy
    ) throws Exception {
        PemTlsMaterial material = importer.importFrom(sourcePath, externalPrivateKeyPath, sourcePassword);
        if (validationPolicy != null) {
            PemTlsMaterial current = currentMaterialLoader.load(targetPaths).orElse(null);
            validator.validate(material, current, validationPolicy);
        }
        return writer.writeAtomically(material, targetPaths, outputPrivateKeyPassword, allowUnencryptedPrivateKey);
    }
}
