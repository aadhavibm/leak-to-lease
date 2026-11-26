package org.springframework.samples.petclinic.vault;

import java.net.URI;
import java.util.Arrays;
import java.util.Map;

import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.Profiles;

public class ProductionEnvironmentChecks implements EnvironmentPostProcessor, Ordered {

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        String profiles = String.join(",",
            environment.getProperty("spring.profiles.active", ""),
            environment.getProperty("spring.profiles.include", ""),
            environment.getProperty("spring.profiles.default", ""));
        if (!environment.acceptsProfiles(Profiles.of("production"))
                && Arrays.stream(profiles.split(",")).map(String::trim).noneMatch("production"::equals)) {
            return;
        }
        String vault = environment.getProperty("spring.cloud.vault.uri", environment.getProperty("VAULT_ADDR"));
        if (vault == null) {
            throw new IllegalStateException("Production requires an explicit HTTPS Vault endpoint before configuration import.");
        }
        if (environment.getProperty("spring.cloud.vault.uri") == null) {
            environment.getPropertySources().addFirst(new MapPropertySource(
                "productionVaultEndpoint", Map.of("spring.cloud.vault.uri", vault)));
        }
        ProductionConnectionChecks.validate(environment, environment.getProperty("spring.datasource.url"));
        if (environment.getProperty("spring.cloud.config.enabled", Boolean.class, true)) {
            validateConfigEndpoint(environment.getProperty("CONFIG_SERVER_URL"));
            for (String location : Binder.get(environment)
                    .bind("spring.config.import", Bindable.listOf(String.class)).orElseGet(java.util.List::of)) {
                String required = location.startsWith("optional:") ? location.substring("optional:".length()) : location;
                if (required.startsWith("configserver:")) {
                    validateConfigEndpoint(required.substring("configserver:".length()));
                }
            }
        }
        environment.getPropertySources().addFirst(new MapPropertySource("productionManagementPolicy", Map.of(
            "management.endpoints.web.exposure.include", "health,info",
            "management.endpoint.health.show-details", "never",
            "management.endpoint.health.show-components", "never",
            "management.endpoint.health.probes.enabled", "true",
            "management.endpoint.health.group.readiness.include", "*",
            "management.server.port", environment.getProperty("management.server.port", "9090"),
            "management.server.address", environment.getProperty("management.server.address", "127.0.0.1")
        )));
    }

    private void validateConfigEndpoint(String config) {
        try {
            URI endpoint = URI.create(config == null ? "" : config);
            if (!"https".equals(endpoint.getScheme()) || endpoint.getHost() == null
                    || endpoint.getUserInfo() != null || endpoint.getQuery() != null || endpoint.getFragment() != null) {
                throw new IllegalArgumentException();
            }
        } catch (IllegalArgumentException error) {
            throw new IllegalStateException("Production requires an explicit HTTPS Config Server URL or disabled remote configuration.");
        }
    }

    @Override
    public int getOrder() {
        return ConfigDataEnvironmentPostProcessor.ORDER - 1;
    }
}
