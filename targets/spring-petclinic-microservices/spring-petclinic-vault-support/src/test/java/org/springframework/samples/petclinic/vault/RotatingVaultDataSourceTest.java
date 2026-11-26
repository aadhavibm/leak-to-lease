package org.springframework.samples.petclinic.vault;

import java.sql.SQLTransientConnectionException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import com.zaxxer.hikari.HikariPoolMXBean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Status;
import org.springframework.vault.core.lease.SecretLeaseContainer;
import org.springframework.vault.core.lease.domain.Lease;
import org.springframework.vault.core.lease.domain.RequestedSecret;
import org.springframework.vault.core.lease.event.AfterSecretLeaseRenewedEvent;
import org.springframework.vault.core.lease.event.SecretLeaseCreatedEvent;
import org.springframework.vault.core.lease.event.SecretLeaseExpiredEvent;
import org.springframework.vault.core.lease.event.SecretLeaseRotatedEvent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class RotatingVaultDataSourceTest {

    private final SecretLeaseContainer container = mock(SecretLeaseContainer.class);
    private final RequestedSecret requested = RequestedSecret.rotating("database/creds/customers");
    private final AtomicLong time = new AtomicLong(1000);
    private final HikariPoolMXBean pool = mock(HikariPoolMXBean.class);
    private final RotatingVaultDataSource source = new RotatingVaultDataSource(container, requested, time::get) {
        @Override
        public HikariPoolMXBean getHikariPoolMXBean() {
            return pool;
        }
    };

    @AfterEach
    void close() {
        source.close();
    }

    private Lease lease(String id, int seconds) {
        return Lease.of(id, Duration.ofSeconds(seconds), true);
    }

    private void create(String id, String username, String password, int seconds) {
        source.onLeaseEvent(new SecretLeaseCreatedEvent(
            requested, lease(id, seconds), Map.of("username", username, "password", password)));
    }

    @Test
    void ownsOneNativeRotatingRequestInsteadOfReRegisteringOnEachFailure() {
        doAnswer(invocation -> {
            create("first", "user-one", "synthetic-one", 30);
            return null;
        }).when(container).start();
        source.afterPropertiesSet();
        verify(container).addRequestedSecret(requested);
        verify(container).afterPropertiesSet();
        verify(container).start();
    }

    @Test
    void atomicallyUpdatesBothCredentialsAndSoftEvictsExistingConnections() {
        create("first", "user-one", "synthetic-one", 30);
        source.onLeaseEvent(new SecretLeaseRotatedEvent(
            requested, lease("first", 30), lease("second", 30),
            Map.of("username", "user-two", "password", "synthetic-two")));
        assertThat(source.getUsername()).isEqualTo("user-two");
        assertThat(source.getPassword()).isEqualTo("synthetic-two");
        verify(pool, org.mockito.Mockito.times(2)).softEvictConnections();
        assertThat(source.leaseHealth().getStatus()).isEqualTo(Status.UP);
    }

    @Test
    void onlyAcceptsEventsForItsOwnDatabaseRequest() {
        source.onLeaseEvent(new SecretLeaseCreatedEvent(
            RequestedSecret.rotating("database/creds/vets"), lease("other", 30),
            Map.of("username", "other", "password", "synthetic-other")));
        assertThat(source.getUsername()).isNull();
        assertThat(source.leaseHealth().getStatus()).isEqualTo(Status.DOWN);
    }

    @Test
    void expiredLeaseFailsNewDatabaseWorkEvenIfMySqlSessionsCouldSurvive() {
        create("first", "user-one", "synthetic-one", 30);
        time.addAndGet(Duration.ofSeconds(31).toNanos());
        assertThat(source.leaseHealth().getStatus()).isEqualTo(Status.DOWN);
        assertThatThrownBy(source::getConnection).isInstanceOf(SQLTransientConnectionException.class);
    }

    @Test
    void renewalExtendsOnlyTheCurrentLeaseDeadline() {
        create("current", "user-one", "synthetic-one", 30);
        time.addAndGet(Duration.ofSeconds(20).toNanos());
        source.onLeaseEvent(new AfterSecretLeaseRenewedEvent(requested, lease("old", 60)));
        time.addAndGet(Duration.ofSeconds(11).toNanos());
        assertThat(source.leaseHealth().getStatus()).isEqualTo(Status.DOWN);
        source.onLeaseEvent(new AfterSecretLeaseRenewedEvent(requested, lease("current", 60)));
        assertThat(source.leaseHealth().getStatus()).isEqualTo(Status.UP);
    }

    @Test
    void expiredOldLeaseCannotDisableTheNewCredentials() {
        create("first", "user-one", "synthetic-one", 30);
        create("second", "user-two", "synthetic-two", 30);
        source.onLeaseEvent(new SecretLeaseExpiredEvent(requested, lease("first", 30)));
        assertThat(source.leaseHealth().getStatus()).isEqualTo(Status.UP);
        source.onLeaseEvent(new SecretLeaseExpiredEvent(requested, lease("second", 30)));
        assertThat(source.leaseHealth().getStatus()).isEqualTo(Status.DOWN);
    }

    @Test
    void failedReacquisitionDoesNotInventValidityAndRecoveryNeedsNoRestart() {
        doAnswer(invocation -> {
            create("first", "user-one", "synthetic-one", 30);
            return null;
        }).when(container).start();
        source.afterPropertiesSet();
        time.addAndGet(Duration.ofSeconds(31).toNanos());
        doThrow(new org.springframework.vault.VaultException("synthetic-private-exception")).when(container).rotate(requested);
        source.maintainLease();
        assertThat(source.leaseHealth().getStatus()).isEqualTo(Status.DOWN);
        doAnswer(invocation -> {
            create("recovered", "user-two", "synthetic-two", 30);
            return null;
        }).when(container).rotate(requested);
        source.maintainLease();
        assertThat(source.leaseHealth().getStatus()).isEqualTo(Status.UP);
        assertThat(source.getUsername()).isEqualTo("user-two");
    }

    @Test
    void startupFailsIfVaultDoesNotProduceAValidCredential() {
        assertThatThrownBy(source::afterPropertiesSet)
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("Managed Vault database pool initialization failed.");
        assertThat(source.isClosed()).isTrue();
    }

    @Test
    void rejectsMalformedCredentialEventsRatherThanKeepingHealthyStatus() {
        create("first", "user-one", "synthetic-one", 30);
        source.onLeaseEvent(new SecretLeaseCreatedEvent(
            requested, lease("bad", 30), Map.of("username", "user-two")));
        assertThat(source.leaseHealth().getStatus()).isEqualTo(Status.DOWN);
    }

    @Test
    void retainedLeaseAfterRenewalFailureDoesNotExtendCredentialValidity() {
        Lease original = lease("first", 20);
        SecretLeaseCreatedEvent created = new SecretLeaseCreatedEvent(
            requested, original, Map.of("username", "user-one", "password", "synthetic-one"));
        source.onLeaseEvent(created);
        time.addAndGet(Duration.ofSeconds(15).toNanos());
        source.onLeaseError(created, new IllegalStateException("synthetic-offline"));
        source.onLeaseEvent(new AfterSecretLeaseRenewedEvent(requested, original));
        time.addAndGet(Duration.ofSeconds(6).toNanos());
        assertThat(source.leaseHealth().getStatus()).isEqualTo(Status.DOWN);
        assertThatThrownBy(source::getConnection).isInstanceOf(SQLTransientConnectionException.class);
    }
}
