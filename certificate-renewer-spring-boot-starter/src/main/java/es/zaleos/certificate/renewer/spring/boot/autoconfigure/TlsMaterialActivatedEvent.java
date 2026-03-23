package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import es.zaleos.certificate.renewer.core.PemActivationResult;
import org.springframework.context.ApplicationEvent;

/**
 * Published after every successful TLS material activation.
 * Subscribers (e.g. JWT verifiers) use this to reload their key material.
 */
public class TlsMaterialActivatedEvent extends ApplicationEvent {

    private final String targetName;
    private final PemActivationResult result;

    public TlsMaterialActivatedEvent(Object source, String targetName, PemActivationResult result) {
        super(source);
        this.targetName = targetName;
        this.result = result;
    }

    public String getTargetName() {
        return targetName;
    }

    public PemActivationResult getResult() {
        return result;
    }
}
