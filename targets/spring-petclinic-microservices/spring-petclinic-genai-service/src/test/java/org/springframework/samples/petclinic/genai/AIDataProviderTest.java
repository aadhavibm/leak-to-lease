package org.springframework.samples.petclinic.genai;

import java.net.URI;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.cloud.client.DefaultServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.http.HttpStatus;
import org.springframework.samples.petclinic.genai.dto.PetRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AIDataProviderTest {

    private final VectorStore vectorStore = mock(VectorStore.class);
    private final DiscoveryClient discoveryClient = mock(DiscoveryClient.class);
    private final AIDataProvider provider = new AIDataProvider(vectorStore, discoveryClient);

    @ParameterizedTest
    @ValueSource(strings = {"listOwners", "addOwner", "addPet"})
    void rejectsCustomerToolsWhenNoServiceInstancesAreAvailable(String tool) {
        when(discoveryClient.getInstances("customers-service")).thenReturn(List.of());

        assertThatThrownBy(() -> {
            switch (tool) {
                case "listOwners" -> provider.getAllOwners();
                case "addOwner" -> provider.addOwnerToPetclinic(
                    new OwnerRequest("George", "Franklin", "1 Main Street", "Madison", "1234567890"));
                case "addPet" -> provider.addPetToOwner(1, new PetRequest(null, "Basil", 1));
                default -> throw new AssertionError(tool);
            }
        }).isInstanceOfSatisfying(ResponseStatusException.class, error -> {
            assertThat(error.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
            assertThat(error.getReason()).contains("Customers service is currently unavailable");
        });
        verifyNoInteractions(vectorStore);
    }

    @Test
    void resolvesFirstAvailableCustomerInstanceWithoutCallingIt() {
        when(discoveryClient.getInstances("customers-service")).thenReturn(List.of(
            new DefaultServiceInstance("customers-1", "customers-service", "localhost", 8081, false),
            new DefaultServiceInstance("customers-2", "customers-service", "localhost", 8082, false)));

        URI uri = ReflectionTestUtils.invokeMethod(provider, "getCustomerServiceUri");

        assertThat(uri).isEqualTo(URI.create("http://localhost:8081"));
        verifyNoInteractions(vectorStore);
    }
}
