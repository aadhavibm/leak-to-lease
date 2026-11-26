package org.springframework.samples.petclinic.customers;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.cloud.vault.config.VaultProperties;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.core.lease.SecretLeaseContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class VaultConfigurationTest {

    @ParameterizedTest
    @ValueSource(strings = {"customers", "vets", "visits"})
    void enablesTheManagedPoolWithoutACompetingStartupCredentialSource(String service) throws Exception {
        Path config = Path.of("../spring-petclinic-" + service + "-service/src/main/resources/application.yml");
        List<PropertySource<?>> documents = new YamlPropertySourceLoader()
            .load(service, new FileSystemResource(config));

        assertThat(documents).hasSize(2);
        assertThat(documents.get(0).getProperty("spring.config.import").toString()).contains("configserver:").doesNotContain("vault://");
        assertThat(documents.get(0).getProperty("spring.cloud.vault.database.enabled")).isEqualTo(false);
        assertThat(documents.get(0).getProperty("petclinic.vault.database.enabled")).isEqualTo(true);
        assertThat(documents.get(1).getProperty("spring.config.activate.on-profile")).isEqualTo("docker");
        assertThat(documents.get(1).getProperty("spring.config.import").toString()).contains("configserver:").doesNotContain("vault://");
    }

    @Test
    void usesNativeLeaseRenewalDefaultsWithoutConnectingToVault() throws Exception {
        assertThat(new VaultProperties().getConfig().getLifecycle().isEnabled()).isTrue();
        VaultOperations operations = mock(VaultOperations.class);
        SecretLeaseContainer container = new SecretLeaseContainer(operations);
        try {
            assertThat(container.isRunning()).isFalse();
            assertThat(container.getMinRenewal()).isEqualTo(Duration.ofSeconds(10));
            assertThat(container.getExpiryThreshold()).isEqualTo(Duration.ofSeconds(60));
            verifyNoInteractions(operations);
        } finally {
            container.destroy();
        }
    }
}
