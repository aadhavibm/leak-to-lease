package org.springframework.samples.petclinic.vault;

import java.nio.file.Path;
import java.util.ArrayList;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.bootstrap.DefaultBootstrapContext;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.http.MediaType;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class ConfigServerImportTest {

    @ParameterizedTest
    @ValueSource(strings = {"customers", "vets", "visits"})
    void productionAndDockerUseTheValidatedEndpointInActualConfigData(String service) {
        MockEnvironment environment = new MockEnvironment()
            .withProperty("spring.profiles.active", "production,docker")
            .withProperty("spring.config.location", Path.of("..", "spring-petclinic-" + service + "-service",
                "src/main/resources/application.yml").toUri().toString())
            .withProperty("CONFIG_SERVER_URL", "https://config.example.test:8443/config")
            .withProperty("spring.cloud.vault.enabled", "false")
            .withProperty("spring.cloud.vault.uri", "https://vault.example.test:8200")
            .withProperty("spring.cloud.vault.authentication", "APPROLE")
            .withProperty("spring.datasource.url", "jdbc:mysql://database.example.test/petclinic?sslMode=VERIFY_IDENTITY");

        RestTemplate rest = new RestTemplate();
        MockRestServiceServer server = MockRestServiceServer.bindTo(rest).build();
        var requests = new ArrayList<java.net.URI>();
        server.expect(ExpectedCount.manyTimes(), request -> {
            assertThat(request.getURI().toString()).startsWith("https://config.example.test:8443/config/");
            requests.add(request.getURI());
        }).andRespond(withSuccess("""
            {"name":"synthetic","profiles":[],"propertySources":[
              {"name":"synthetic-config","source":{"test.remote.config":"loaded"}}
            ]}
            """, MediaType.APPLICATION_JSON));
        DefaultBootstrapContext bootstrap = new DefaultBootstrapContext();
        bootstrap.register(RestTemplate.class, context -> rest);
        ProductionEnvironmentChecks checks = new ProductionEnvironmentChecks();
        checks.postProcessEnvironment(environment, null);
        ConfigDataEnvironmentPostProcessor.applyTo(environment, null, bootstrap);

        assertThat(environment.getActiveProfiles()).containsExactlyInAnyOrder("production", "docker");
        assertThat(requests).isNotEmpty();
        assertThat(requests).anyMatch(uri -> uri.getPath().contains("production"));
        assertThat(requests).anyMatch(uri -> uri.getPath().contains("docker"));
        assertThat(environment.getProperty("test.remote.config")).isEqualTo("loaded");
        assertThat(environment.getProperty("spring.config.import"))
            .isEqualTo("configserver:https://config.example.test:8443/config");
        // Inspect every loaded import, not only the winning profile document.
        environment.getPropertySources().forEach(properties -> {
            Object location = properties.getProperty("spring.config.import");
            if (location != null) {
                assertThat(environment.resolveRequiredPlaceholders(location.toString()))
                    .endsWith("configserver:https://config.example.test:8443/config");
            }
        });
        server.verify();
        assertThatCode(() -> checks.postProcessEnvironment(environment, null))
            .doesNotThrowAnyException();
    }
}
