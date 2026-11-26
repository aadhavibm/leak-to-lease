package org.springframework.samples.petclinic.vault;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLTransientConnectionException;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;

import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.HikariPoolMXBean;
import com.zaxxer.hikari.util.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.health.contributor.Health;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.cloud.vault.config.VaultProperties;
import org.springframework.util.StringUtils;
import org.springframework.vault.authentication.SessionManager;
import org.springframework.vault.authentication.event.AuthenticationEventMulticaster;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.core.lease.SecretLeaseContainer;
import org.springframework.vault.core.lease.LeaseEndpoints;
import org.springframework.vault.core.lease.domain.RequestedSecret;
import org.springframework.vault.core.lease.domain.Lease;
import org.springframework.vault.core.lease.event.AfterSecretLeaseRenewedEvent;
import org.springframework.vault.core.lease.event.LeaseErrorListener;
import org.springframework.vault.core.lease.event.LeaseListener;
import org.springframework.vault.core.lease.event.SecretLeaseCreatedEvent;
import org.springframework.vault.core.lease.event.SecretLeaseEvent;
import org.springframework.vault.core.lease.event.SecretLeaseExpiredEvent;
import org.springframework.vault.support.LeaseStrategy;

public class RotatingVaultDataSource extends HikariDataSource
        implements InitializingBean, LeaseListener, LeaseErrorListener {

    private static final Logger log = LoggerFactory.getLogger(RotatingVaultDataSource.class);
    private final SecretLeaseContainer leases;
    private final RequestedSecret requested;
    private final LongSupplier nanoTime;
    private final AtomicBoolean maintaining = new AtomicBoolean();
    private final ScheduledExecutorService recovery = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread = new Thread(task, "vault-database-pool-recovery");
        thread.setDaemon(true);
        return thread;
    });
    private volatile long expiresAt;
    private volatile long rolloverWindow;
    private volatile Lease currentLease;
    private volatile boolean initialized;
    private AuthenticationEventMulticaster authenticationEvents;

    RotatingVaultDataSource(VaultOperations operations, ConfigurableEnvironment environment, SessionManager sessionManager) {
        this(new SecretLeaseContainer(operations), RequestedSecret.rotating(
            environment.getRequiredProperty("spring.cloud.vault.database.backend")
                + "/creds/" + environment.getRequiredProperty("spring.cloud.vault.database.role")),
            System::nanoTime);
        if (sessionManager instanceof AuthenticationEventMulticaster events) {
            authenticationEvents = events;
        }
        VaultProperties.ConfigLifecycle lifecycle = Binder.get(environment)
            .bind("spring.cloud.vault.config.lifecycle", VaultProperties.ConfigLifecycle.class)
            .orElseGet(VaultProperties.ConfigLifecycle::new);
        if (lifecycle.getMinRenewal() != null) {
            leases.setMinRenewal(lifecycle.getMinRenewal());
        }
        if (lifecycle.getExpiryThreshold() != null) {
            leases.setExpiryThreshold(lifecycle.getExpiryThreshold());
        }
    }

    RotatingVaultDataSource(SecretLeaseContainer leases, RequestedSecret requested, LongSupplier nanoTime) {
        this.leases = leases;
        this.requested = requested;
        this.nanoTime = nanoTime;
        if (requested.getMode() != RequestedSecret.Mode.ROTATE) {
            throw new IllegalStateException("Vault database secrets must use rotating lease metadata.");
        }
    }

    @Override
    public void afterPropertiesSet() {
        leases.setLeaseStrategy(LeaseStrategy.retainOnError());
        leases.setLeaseEndpoints(LeaseEndpoints.Leases);
        leases.addLeaseListener(this);
        leases.addErrorListener(this);
        try {
            leases.addRequestedSecret(requested);
            leases.afterPropertiesSet();
            leases.start();
            if (!usable()) {
                throw new IllegalStateException("Vault did not provide a usable database lease.");
            }
            if (authenticationEvents != null) {
                // Attach only after native bootstrap has installed its scheduler and initial lease.
                authenticationEvents.addAuthenticationListener(leases.getAuthenticationListener());
                authenticationEvents.addErrorListener(leases.getAuthenticationErrorListener());
            }
            initialized = true;
            recovery.scheduleWithFixedDelay(this::maintainLease, 1, 1, TimeUnit.SECONDS);
        } catch (RuntimeException error) {
            close();
            throw new IllegalStateException("Managed Vault database pool initialization failed.");
        }
    }

    @Override
    public synchronized void onLeaseEvent(SecretLeaseEvent event) {
        if (!event.getSource().getPath().equals(requested.getPath())) {
            return;
        }
        if (event instanceof SecretLeaseCreatedEvent created) {
            Object username = created.getSecrets().get("username");
            Object password = created.getSecrets().get("password");
            if (!(username instanceof String user) || !StringUtils.hasText(user)
                    || !(password instanceof String secret) || !StringUtils.hasText(secret)
                    || !event.getLease().hasLeaseId() || event.getLease().getLeaseDuration().isZero()
                    || event.getLease().getLeaseDuration().isNegative()) {
                expiresAt = 0;
                log.error("VAULT_DATABASE_CREDENTIALS_INVALID");
                return;
            }
            setCredentials(Credentials.of(user, secret));
            currentLease = event.getLease();
            extend(event.getLease().getLeaseDuration());
            HikariPoolMXBean pool = getHikariPoolMXBean();
            if (pool != null) {
                pool.softEvictConnections();
            }
        } else if (currentLease != null && currentLease.getLeaseId().equals(event.getLease().getLeaseId())) {
            if (event instanceof AfterSecretLeaseRenewedEvent) {
                // RetainOnError republishes the same Lease; it is not a successful server renewal.
                if (event.getLease() != currentLease) {
                    currentLease = event.getLease();
                    extend(event.getLease().getLeaseDuration());
                }
            } else if (event instanceof SecretLeaseExpiredEvent) {
                expiresAt = 0;
            }
        }
    }

    private void extend(Duration duration) {
        long remaining = duration.toNanos();
        expiresAt = nanoTime.getAsLong() + remaining;
        rolloverWindow = Math.min(TimeUnit.SECONDS.toNanos(5), remaining / 3);
    }

    @Override
    public void onLeaseError(SecretLeaseEvent event, Exception error) {
        if (event.getSource().getPath().equals(requested.getPath())) {
            log.warn("VAULT_DATABASE_LEASE_OPERATION_FAILED");
        }
    }

    void maintainLease() {
        if (isClosed() || !initialized || nanoTime.getAsLong() < expiresAt - rolloverWindow
                || !maintaining.compareAndSet(false, true)) {
            return;
        }
        try {
            try {
                leases.rotate(requested);
            } catch (IllegalStateException terminalLease) {
                // A failed terminal replacement leaves Lease.none(), which cannot be rotated.
                // Restart only this single-request container, retaining native scheduling.
                leases.stop();
                leases.start();
            }
        } catch (RuntimeException error) {
            log.warn("VAULT_DATABASE_REACQUISITION_FAILED ({})", error.getClass().getSimpleName());
        } finally {
            maintaining.set(false);
        }
    }

    private boolean usable() {
        return currentLease != null && nanoTime.getAsLong() < expiresAt && !isClosed();
    }

    public Health leaseHealth() {
        return usable() ? Health.up().build()
            : Health.down().withDetail("reason", "NO_USABLE_DATABASE_LEASE").build();
    }

    @Override
    public Connection getConnection() throws SQLException {
        if (!usable()) {
            throw new SQLTransientConnectionException("No usable Vault database lease is available.");
        }
        Connection connection = super.getConnection();
        if (!usable()) {
            connection.close();
            throw new SQLTransientConnectionException("Vault database lease expired while obtaining a connection.");
        }
        return connection;
    }

    @Override
    public void close() {
        if (isClosed()) {
            return;
        }
        initialized = false;
        recovery.shutdownNow();
        if (authenticationEvents != null) {
            authenticationEvents.removeAuthenticationListener(leases.getAuthenticationListener());
            authenticationEvents.removeErrorListener(leases.getAuthenticationErrorListener());
        }
        leases.removeLeaseListener(this);
        leases.removeLeaseErrorListener(this);
        super.close();
        try {
            leases.destroy();
        } catch (Exception error) {
            log.warn("VAULT_DATABASE_LEASE_CLEANUP_FAILED");
        }
    }
}
