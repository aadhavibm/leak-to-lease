package org.springframework.samples.petclinic.vault;

import javax.sql.DataSource;
import java.sql.SQLException;

import com.zaxxer.hikari.HikariConfig;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceProperties;
import org.springframework.cloud.vault.config.VaultAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.authentication.SessionManager;

@AutoConfiguration(before = DataSourceAutoConfiguration.class, after = VaultAutoConfiguration.class)
@ConditionalOnProperty(name = "spring.cloud.vault.enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnProperty(name = "petclinic.vault.database.enabled", havingValue = "true")
@EnableConfigurationProperties(DataSourceProperties.class)
public class VaultPoolAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(DataSource.class)
    RotatingVaultDataSource dataSource(
            DataSourceProperties properties, VaultOperations operations, ConfigurableEnvironment environment,
            ObjectProvider<SessionManager> sessionManager) {
        HikariConfig configuration = Binder.get(environment)
            .bind("spring.datasource.hikari", HikariConfig.class).orElseGet(HikariConfig::new);
        if (configuration.getJdbcUrl() == null) {
            configuration.setJdbcUrl(properties.determineUrl());
        }
        if (configuration.getDriverClassName() == null) {
            configuration.setDriverClassName(properties.determineDriverClassName());
        }
        ProductionConnectionChecks.validatePool(environment, configuration);
        RotatingVaultDataSource source = new RotatingVaultDataSource(operations, environment, sessionManager.getIfAvailable());
        configuration.copyStateTo(source);
        return source;
    }

    @Bean
    @ConditionalOnBean(RotatingVaultDataSource.class)
    HealthIndicator vaultDatabaseLeaseHealthIndicator(DataSource source) throws SQLException {
        return source.unwrap(RotatingVaultDataSource.class)::leaseHealth;
    }
}
