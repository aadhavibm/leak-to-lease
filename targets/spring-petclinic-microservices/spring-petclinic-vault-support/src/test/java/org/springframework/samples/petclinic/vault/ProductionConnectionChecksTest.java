package org.springframework.samples.petclinic.vault;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.mock.env.MockEnvironment;
import com.zaxxer.hikari.HikariConfig;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ProductionConnectionChecksTest {

    private MockEnvironment environment() {
        MockEnvironment environment = new MockEnvironment()
            .withProperty("spring.cloud.vault.uri", "https://vault.example.test:8200")
            .withProperty("spring.cloud.vault.authentication", "APPROLE");
        environment.setActiveProfiles("production");
        return environment;
    }

    @Test
    void acceptsVerifiedTlsAndNativeAppRoleWithoutAnyNetworkCalls() {
        assertThatCode(() -> ProductionConnectionChecks.validate(
            environment(), "jdbc:mysql://database.example.test/petclinic?sslMode=VERIFY_IDENTITY"))
            .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "jdbc:mysql://database.example.test/petclinic",
        "jdbc:mysql://database.example.test/petclinic?sslMode=REQUIRED",
        "jdbc:mysql://database.example.test/petclinic?sslMode=VERIFY_IDENTITY&useSSL=false",
        "jdbc:mysql://database.example.test/petclinic?sslMode=VERIFY_IDENTITY&allowPublicKeyRetrieval=true",
        "jdbc:mysql://database.example.test/petclinic?sslMode=VERIFY_IDENTITY&password=synthetic-only",
        "jdbc:mysql://database.example.test/petclinic?sslMode=VERIFY_IDENTITY&sslMode=DISABLED"
    })
    void rejectsUnverifiedOrContradictoryDatabaseTls(String url) {
        assertThatThrownBy(() -> ProductionConnectionChecks.validate(environment(), url))
            .isInstanceOf(IllegalStateException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://vault.example.test:8200", "https://user:synthetic@vault.example.test", "https://vault.example.test?token=synthetic"})
    void rejectsUnsafeVaultUrls(String address) {
        assertThatThrownBy(() -> ProductionConnectionChecks.validate(
            environment().withProperty("spring.cloud.vault.uri", address),
            "jdbc:mysql://database.example.test/petclinic?sslMode=VERIFY_IDENTITY"))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void productionRejectsStaticApplicationTokenButDevelopmentDefaultsRemainUsable() {
        assertThatThrownBy(() -> ProductionConnectionChecks.validate(
            environment().withProperty("spring.cloud.vault.authentication", "TOKEN"),
            "jdbc:mysql://database.example.test/petclinic?sslMode=VERIFY_IDENTITY"))
            .isInstanceOf(IllegalStateException.class);
        assertThatCode(() -> ProductionConnectionChecks.validate(new MockEnvironment(), "jdbc:mysql://localhost/petclinic"))
            .doesNotThrowAnyException();
    }

    @Test
    void validatesProductionBeforeConfigDataCanContactVault() {
        MockEnvironment environment = environment()
            .withProperty("spring.profiles.active", "production")
            .withProperty("spring.cloud.vault.uri", "http://insecure.example.test")
            .withProperty("spring.datasource.url", "jdbc:mysql://database.example.test/petclinic?sslMode=VERIFY_IDENTITY");
        ProductionEnvironmentChecks checks = new ProductionEnvironmentChecks();
        assertThat(checks.getOrder()).isLessThan(ConfigDataEnvironmentPostProcessor.ORDER);
        assertThatThrownBy(() -> checks.postProcessEnvironment(environment, null))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void explicitRemoteConfigCanBeDisabledButNotFetchedOverHttp() {
        MockEnvironment environment = environment()
            .withProperty("spring.profiles.active", "production")
            .withProperty("spring.datasource.url", "jdbc:mysql://database.example.test/petclinic?sslMode=VERIFY_IDENTITY")
            .withProperty("CONFIG_SERVER_URL", "http://insecure-config.example.test");
        ProductionEnvironmentChecks checks = new ProductionEnvironmentChecks();
        assertThatThrownBy(() -> checks.postProcessEnvironment(environment, null))
            .isInstanceOf(IllegalStateException.class);
        environment.withProperty("spring.cloud.config.enabled", "false");
        assertThatCode(() -> checks.postProcessEnvironment(environment, null)).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "configserver:http://insecure-config.example.test",
        "optional:configserver:http://insecure-config.example.test",
        "configserver:",
        "configserver:https://config.example.test/#fragment",
        "configserver:https://config.example.test/?credential=synthetic",
        "configserver:https://config.example.test/,optional:configserver:http://insecure-config.example.test"
    })
    void validatesActualExplicitImportsRatherThanOnlyTheUrlVariable(String location) {
        MockEnvironment environment = environment()
            .withProperty("spring.profiles.active", "production,docker")
            .withProperty("spring.datasource.url", "jdbc:mysql://database.example.test/petclinic?sslMode=VERIFY_IDENTITY")
            .withProperty("CONFIG_SERVER_URL", "https://config.example.test/")
            .withProperty("spring.config.import", location);
        assertThatThrownBy(() -> new ProductionEnvironmentChecks().postProcessEnvironment(environment, null))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void programmaticallyActivatedProductionAlsoValidatesTheActualImport() {
        MockEnvironment environment = environment()
            .withProperty("spring.datasource.url", "jdbc:mysql://database.example.test/petclinic?sslMode=VERIFY_IDENTITY")
            .withProperty("CONFIG_SERVER_URL", "https://config.example.test/")
            .withProperty("spring.config.import", "configserver:http://insecure-config.example.test");
        environment.setActiveProfiles("production", "docker");
        assertThatThrownBy(() -> new ProductionEnvironmentChecks().postProcessEnvironment(environment, null))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void poolPropertiesCannotBypassTheVerifiedConnectionUrl() {
        HikariConfig configuration = new HikariConfig();
        configuration.setJdbcUrl("jdbc:mysql://database.example.test/petclinic?sslMode=VERIFY_IDENTITY");
        configuration.addDataSourceProperty("sslMode", "DISABLED");
        assertThatThrownBy(() -> ProductionConnectionChecks.validatePool(environment(), configuration))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void alternateDataSourceCannotBypassConnectionValidation() {
        HikariConfig configuration = new HikariConfig();
        configuration.setJdbcUrl("jdbc:mysql://database.example.test/petclinic?sslMode=VERIFY_IDENTITY");
        configuration.setDataSourceClassName("unsupported.DataSource");
        assertThatThrownBy(() -> ProductionConnectionChecks.validatePool(environment(), configuration))
            .isInstanceOf(IllegalStateException.class);
    }
}
