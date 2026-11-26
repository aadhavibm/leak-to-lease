package org.springframework.samples.petclinic.vault;

import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.sql.SQLTransientConnectionException;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.health.contributor.Status;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.vault.core.RestOperationsCallback;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.core.lease.SecretLeaseContainer;
import org.springframework.vault.core.lease.domain.Lease;
import org.springframework.vault.core.lease.domain.RequestedSecret;
import org.springframework.vault.support.VaultResponse;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEFAULTS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RotatingVaultDataSourceNativeTest {

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void recoversFromNativeTerminalRenewalAndFailedReplacementWithoutRestartingThePool(boolean throwOnRead)
            throws Exception {
        String path = "database/creds/customers";
        AtomicInteger reads = new AtomicInteger();
        AtomicInteger renewals = new AtomicInteger();
        AtomicBoolean restored = new AtomicBoolean();
        AtomicBoolean recover = new AtomicBoolean();
        VaultOperations operations = mock(VaultOperations.class);
        when(operations.read(path)).thenAnswer(invocation -> {
            int attempt = reads.incrementAndGet();
            if (attempt == 1) {
                return credentials("first", "FIRSTUSER", "synthetic-first", 1);
            }
            if (restored.get()) {
                return credentials("recovered", "SECONDUSER", "synthetic-second", 2);
            }
            if (throwOnRead) {
                throw new IllegalStateException("Synthetic credential endpoint unavailable");
            }
            return null;
        });
        RestOperations rest = mock(RestOperations.class, invocation -> {
            if (invocation.getMethod().getName().equals("exchange")
                    && invocation.getArgument(0).equals("sys/leases/renew")) {
                renewals.incrementAndGet();
                if (!restored.get()) {
                    throw HttpClientErrorException.create(HttpStatus.BAD_REQUEST, "Bad Request", HttpHeaders.EMPTY,
                        "{\"errors\":[\"lease not found\"]}".getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
                }
                return ResponseEntity.ok(Map.of("lease_id", "recovered", "lease_duration", 30, "renewable", true));
            }
            return RETURNS_DEFAULTS.answer(invocation);
        });
        doAnswer(invocation -> ((RestOperationsCallback<?>) invocation.getArgument(0)).doWithRestOperations(rest))
            .when(operations).doWithSession(any());
        SecretLeaseContainer container = new SecretLeaseContainer(operations);
        container.setMinRenewal(Duration.ofMillis(10));
        container.setExpiryThreshold(Duration.ofMillis(500));
        RequestedSecret requested = RequestedSecret.rotating(path);
        String url = "jdbc:hsqldb:mem:" + UUID.randomUUID();
        try (var admin = DriverManager.getConnection(url, "SA", "");
                var sql = admin.createStatement();
                RotatingVaultDataSource source = new RotatingVaultDataSource(container, requested, System::nanoTime) {
                    @Override
                    void maintainLease() {
                        if (recover.get()) {
                            super.maintainLease();
                        }
                    }
                }) {
            sql.execute("CREATE USER FIRSTUSER PASSWORD 'synthetic-first' ADMIN");
            sql.execute("CREATE USER SECONDUSER PASSWORD 'synthetic-second' ADMIN");
            sql.execute("CREATE TABLE PENDING_WORK (VALUE INTEGER)");
            source.setJdbcUrl(url);
            source.setMinimumIdle(0);
            source.setMaximumPoolSize(2);
            source.afterPropertiesSet();
            try (var borrowed = source.getConnection(); var transaction = borrowed.createStatement()) {
                var originalPool = source.getHikariPoolMXBean();
                borrowed.setAutoCommit(false);
                transaction.executeUpdate("INSERT INTO PENDING_WORK VALUES (1)");
                await().atMost(Duration.ofSeconds(5)).pollInterval(Duration.ofMillis(10))
                    .untilAsserted(() -> assertThat(nativeLease(container, requested)).isSameAs(Lease.none()));
                assertThat(renewals.get()).isEqualTo(1);
                assertThat(reads.get()).isEqualTo(2);
                assertThatThrownBy(() -> container.rotate(requested)).isInstanceOf(IllegalStateException.class);
                assertUnavailable(source);

                recover.set(true);
                await().atMost(Duration.ofSeconds(5)).until(() -> reads.get() >= 3);
                assertUnavailable(source);
                restored.set(true);
                await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
                    assertThat(source.leaseHealth().getStatus()).isEqualTo(Status.UP);
                    assertThat(source.getUsername()).isEqualTo("SECONDUSER");
                });
                try (var fresh = source.getConnection(); var query = fresh.createStatement();
                        var result = query.executeQuery("VALUES CURRENT_USER")) {
                    assertThat(result.next()).isTrue();
                    assertThat(result.getString(1)).isEqualTo("SECONDUSER");
                }
                try (var result = transaction.executeQuery("SELECT COUNT(*) FROM PENDING_WORK")) {
                    assertThat(result.next()).isTrue();
                    assertThat(result.getInt(1)).isEqualTo(1);
                }
                borrowed.commit();
                // The recovered lease must still be renewed by the real native scheduler.
                await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
                    assertThat(renewals.get()).isGreaterThanOrEqualTo(2);
                    assertThat(nativeLease(container, requested).getLeaseDuration()).isEqualTo(Duration.ofSeconds(30));
                });
                assertThat(source.isClosed()).isFalse();
                assertThat(source.getHikariPoolMXBean()).isSameAs(originalPool);
                assertThat(source.leaseHealth().getStatus()).isEqualTo(Status.UP);
            }
        }
        assertThat(container.isRunning()).isFalse();
    }

    private static void assertUnavailable(RotatingVaultDataSource source) {
        assertThat(source.leaseHealth().getStatus()).isEqualTo(Status.DOWN);
        assertThatThrownBy(source::getConnection).isInstanceOf(SQLTransientConnectionException.class);
    }

    private static Lease nativeLease(SecretLeaseContainer container, RequestedSecret requested) throws Exception {
        var renewals = SecretLeaseContainer.class.getDeclaredField("renewals");
        renewals.setAccessible(true);
        Object scheduler = ((Map<?, ?>) renewals.get(container)).get(requested);
        var getLease = scheduler.getClass().getDeclaredMethod("getLease");
        getLease.setAccessible(true);
        return (Lease) getLease.invoke(scheduler);
    }

    private static VaultResponse credentials(String leaseId, String username, String password, int seconds) {
        VaultResponse response = new VaultResponse();
        response.setLeaseId(leaseId);
        response.setLeaseDuration(seconds);
        response.setRenewable(true);
        response.setData(Map.of("username", username, "password", password));
        return response;
    }
}
