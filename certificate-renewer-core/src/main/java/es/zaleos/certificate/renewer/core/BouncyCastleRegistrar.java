package es.zaleos.certificate.renewer.core;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Centralized, idempotent registration of the BouncyCastle JCE provider.
 *
 * <p>Call {@link #ensureRegistered()} once from any component that requires BouncyCastle.
 * Subsequent calls are no-ops.
 */
public final class BouncyCastleRegistrar {

    private BouncyCastleRegistrar() {}

    /**
     * Registers the BouncyCastle provider if not already registered.
     */
    public static void ensureRegistered() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
