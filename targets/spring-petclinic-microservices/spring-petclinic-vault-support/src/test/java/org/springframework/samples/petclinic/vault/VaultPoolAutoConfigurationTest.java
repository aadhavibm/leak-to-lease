package org.springframework.samples.petclinic.vault;

import java.sql.DriverManager;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.authentication.AuthenticationEventPublisher;
import org.springframework.vault.authentication.SessionManager;
import org.springframework.vault.authentication.event.AuthenticationErrorListener;
import org.springframework.vault.authentication.event.AuthenticationListener;
import org.springframework.vault.authentication.event.LoginTokenExpiredEvent;
import org.springframework.vault.authentication.event.LoginTokenRenewalFailedEvent;
import org.springframework.vault.core.lease.domain.Lease;
import org.springframework.vault.core.lease.domain.RequestedSecret;
import org.springframework.vault.core.lease.event.SecretLeaseCreatedEvent;
import org.springframework.vault.support.VaultResponse;
import org.springframework.vault.support.VaultToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class VaultPoolAutoConfigurationTest {

    @Test
    void bindsHikariSettingsWithoutCallingAnUninitializedConnectionGetter() {
        runner("jdbc:hsqldb:mem:" + UUID.randomUUID()).run(context -> {
            assertThat(context).hasNotFailed();
            RotatingVaultDataSource source = context.getBean(RotatingVaultDataSource.class);
            assertThat(source.getConnectionTimeout()).isEqualTo(2000);
            assertThat(source.leaseHealth().getStatus().getCode()).isEqualTo("UP");
        });
    }

    @Test
    void healthContributorUnwrapsAnInterfaceBasedTracingProxy() {
        runner("jdbc:hsqldb:mem:" + UUID.randomUUID()).run(context -> {
            RotatingVaultDataSource source = context.getBean(RotatingVaultDataSource.class);
            ProxyFactory factory = new ProxyFactory(source);
            factory.setInterfaces(DataSource.class);
            DataSource proxy = (DataSource) factory.getProxy();
            assertThat(new VaultPoolAutoConfiguration().vaultDatabaseLeaseHealthIndicator(proxy)
                .health().getStatus().getCode()).isEqualTo("UP");
        });
    }

    @Test
    void actualPoolUsesNewCredentialsWithoutInterruptingBorrowedConnections() throws Exception {
        String url = "jdbc:hsqldb:mem:" + UUID.randomUUID();
        try (var admin = DriverManager.getConnection(url, "SA", "");
                var sql = admin.createStatement()) {
            sql.execute("CREATE USER FIRSTUSER PASSWORD 'synthetic-first' ADMIN");
            sql.execute("CREATE USER SECONDUSER PASSWORD 'synthetic-second' ADMIN");
            runner(url).run(context -> {
                assertThat(context).hasNotFailed();
                RotatingVaultDataSource source = context.getBean(RotatingVaultDataSource.class);
                try (var borrowed = source.getConnection()) {
                    source.onLeaseEvent(new SecretLeaseCreatedEvent(
                        RequestedSecret.rotating("database/creds/customers"), Lease.of("second", Duration.ofSeconds(60), true),
                        Map.of("username", "SECONDUSER", "password", "synthetic-second")));
                    assertThat(borrowed.isValid(1)).isTrue();
                    try (var fresh = source.getConnection(); var query = fresh.createStatement();
                            var result = query.executeQuery("VALUES CURRENT_USER")) {
                        assertThat(result.next()).isTrue();
                        assertThat(result.getString(1)).isEqualTo("SECONDUSER");
                    }
                }
            });
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void nativeAuthenticationEventsReacquireSecretsAndListenersAreDetachedOnClose(boolean renewalFailure) {
        EventSessionManager manager = spy(new EventSessionManager());
        ArgumentCaptor<AuthenticationListener> listener = ArgumentCaptor.forClass(AuthenticationListener.class);
        ArgumentCaptor<AuthenticationErrorListener> errorListener = ArgumentCaptor.forClass(AuthenticationErrorListener.class);
        runner("jdbc:hsqldb:mem:" + UUID.randomUUID(), manager)
            .withBean(SessionManager.class, () -> manager).run(context -> {
                assertThat(context).hasNotFailed();
                RotatingVaultDataSource source = context.getBean(RotatingVaultDataSource.class);
                VaultOperations operations = context.getBean(VaultOperations.class);
                verify(operations, times(1)).read("database/creds/customers");
                verify(manager).addAuthenticationListener(listener.capture());
                verify(manager).addErrorListener(errorListener.capture());
                VaultResponse replacement = new VaultResponse();
                replacement.setData(Map.of("username", "SECONDUSER", "password", "synthetic-second"));
                replacement.setLeaseId("after-token-event");
                replacement.setLeaseDuration(60);
                replacement.setRenewable(true);
                when(operations.read("database/creds/customers")).thenReturn(replacement);
                if (renewalFailure) {
                    manager.multicastEvent(new LoginTokenRenewalFailedEvent(
                        manager.getSessionToken(), new IllegalStateException("Synthetic token renewal failure")));
                } else {
                    manager.multicastEvent(new LoginTokenExpiredEvent(manager.getSessionToken()));
                }
                await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
                    assertThat(source.getUsername()).isEqualTo("SECONDUSER");
                    assertThat(source.leaseHealth().getStatus().getCode()).isEqualTo("UP");
                });
            });
        verify(manager).removeAuthenticationListener(listener.getValue());
        verify(manager).removeErrorListener(errorListener.getValue());
    }

    private ApplicationContextRunner runner(String url) {
        return runner(url, null);
    }

    private ApplicationContextRunner runner(String url, EventSessionManager manager) {
        VaultOperations operations = mock(VaultOperations.class);
        VaultResponse response = new VaultResponse();
        response.setData(Map.of("username", "FIRSTUSER", "password", "synthetic-first"));
        response.setLeaseId("first");
        response.setLeaseDuration(60);
        response.setRenewable(true);
        AtomicBoolean bootstrap = new AtomicBoolean(true);
        when(operations.read("database/creds/customers")).thenAnswer(invocation -> {
            if (manager != null && bootstrap.getAndSet(false)) {
                manager.multicastEvent(new LoginTokenExpiredEvent(manager.getSessionToken()));
            }
            return response;
        });
        return new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(VaultPoolAutoConfiguration.class))
            .withBean(VaultOperations.class, () -> operations)
            .withPropertyValues(
                "spring.cloud.vault.enabled=true", "spring.cloud.vault.database.enabled=false",
                "petclinic.vault.database.enabled=true",
                "spring.cloud.vault.database.backend=database", "spring.cloud.vault.database.role=customers",
                "spring.datasource.url=" + url, "spring.datasource.hikari.connection-timeout=2000",
                "spring.datasource.hikari.minimum-idle=0", "spring.datasource.hikari.maximum-pool-size=2");
    }

    private static class EventSessionManager extends AuthenticationEventPublisher implements SessionManager {
        @Override
        public VaultToken getSessionToken() {
            return VaultToken.of("synthetic-token");
        }
    }
}
