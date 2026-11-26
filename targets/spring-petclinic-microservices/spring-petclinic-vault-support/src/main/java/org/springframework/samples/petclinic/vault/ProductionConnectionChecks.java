package org.springframework.samples.petclinic.vault;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.zaxxer.hikari.HikariConfig;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;

final class ProductionConnectionChecks {

    private ProductionConnectionChecks() {
    }

    static void validate(Environment environment, String jdbcUrl) {
        if (!environment.acceptsProfiles(Profiles.of("production"))) {
            return;
        }
        try {
            URI vault = URI.create(environment.getRequiredProperty("spring.cloud.vault.uri"));
            if (!"https".equals(vault.getScheme()) || vault.getHost() == null
                    || vault.getUserInfo() != null || vault.getRawQuery() != null || vault.getFragment() != null) {
                throw new IllegalArgumentException();
            }
            String authentication = environment.getProperty("spring.cloud.vault.authentication", "TOKEN");
            if (!Set.of("APPROLE", "KUBERNETES", "CERT").contains(authentication.toUpperCase(java.util.Locale.ROOT))) {
                throw new IllegalArgumentException();
            }
            if (jdbcUrl == null || !jdbcUrl.startsWith("jdbc:mysql://")) {
                throw new IllegalArgumentException();
            }
            URI database = URI.create(jdbcUrl.substring("jdbc:".length()));
            Map<String, String> parameters = new HashMap<>();
            for (String pair : database.getRawQuery() == null ? new String[0] : database.getRawQuery().split("&")) {
                String[] parts = pair.split("=", 2);
                String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8).toLowerCase(java.util.Locale.ROOT);
                String value = parts.length == 2 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
                if (parameters.putIfAbsent(key, value) != null) {
                    throw new IllegalArgumentException();
                }

            }
            if (database.getHost() == null || database.getUserInfo() != null
                    || !"VERIFY_IDENTITY".equalsIgnoreCase(parameters.get("sslmode"))
                    || parameters.containsKey("user") || parameters.containsKey("password")
                    || "false".equalsIgnoreCase(parameters.get("usessl"))
                    || "true".equalsIgnoreCase(parameters.get("allowpublickeyretrieval"))) {
                throw new IllegalArgumentException();
            }
        } catch (IllegalArgumentException error) {
            throw new IllegalStateException(
                "Production requires HTTPS Vault with APPROLE/KUBERNETES/CERT authentication and "
                    + "MySQL sslMode=VERIFY_IDENTITY without embedded credentials or insecure overrides.");
        }
    }

    static void validatePool(Environment environment, HikariConfig configuration) {
        validate(environment, configuration.getJdbcUrl());
        if (!environment.acceptsProfiles(Profiles.of("production"))) {
            return;
        }
        if (configuration.getDataSource() != null || configuration.getDataSourceClassName() != null
                || configuration.getDataSourceJNDI() != null) {
            throw new IllegalStateException("Production requires the validated MySQL JDBC URL, not an alternate DataSource.");
        }
        configuration.getDataSourceProperties().forEach((key, value) -> {
            String name = key.toString().toLowerCase(java.util.Locale.ROOT);
            String setting = value.toString();
            if (Set.of("user", "username", "password").contains(name)
                    || ("sslmode".equals(name) && !"VERIFY_IDENTITY".equalsIgnoreCase(setting))
                    || (Set.of("usessl", "verifyservercertificate").contains(name) && "false".equalsIgnoreCase(setting))
                    || ("allowpublickeyretrieval".equals(name) && "true".equalsIgnoreCase(setting))) {
                throw new IllegalStateException("Production Hikari properties cannot override verified TLS or Vault credentials.");
            }
        });
    }
}
