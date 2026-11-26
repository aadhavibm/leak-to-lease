package org.springframework.samples.petclinic.api.boundary.web;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JAutoConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.samples.petclinic.api.application.CustomersServiceClient;
import org.springframework.samples.petclinic.api.application.VisitsServiceClient;
import org.springframework.samples.petclinic.api.dto.OwnerDetails;
import org.springframework.samples.petclinic.api.dto.PetDetails;
import org.springframework.samples.petclinic.api.dto.VisitDetails;
import org.springframework.samples.petclinic.api.dto.Visits;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.net.ConnectException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@WebFluxTest(controllers = ApiGatewayController.class)
@Import({ReactiveResilience4JAutoConfiguration.class, CircuitBreakerConfiguration.class})
@ActiveProfiles("test")
class ApiGatewayControllerTest {

    @MockitoBean
    private CustomersServiceClient customersServiceClient;

    @MockitoBean
    private VisitsServiceClient visitsServiceClient;

    @Autowired
    private WebTestClient client;


    @Test
    void getOwnerDetails_withAvailableVisitsService() {
        PetDetails cat = PetDetails.PetDetailsBuilder.aPetDetails()
            .id(20)
            .name("Garfield")
            .visits(new ArrayList<>())
            .build();
        OwnerDetails owner = OwnerDetails.OwnerDetailsBuilder.anOwnerDetails()
            .pets(List.of(cat))
            .build();
        Mockito
            .when(customersServiceClient.getOwner(1))
            .thenReturn(Mono.just(owner));

        VisitDetails visit = new VisitDetails(300, cat.id(), null, "First visit");
        Visits visits = new Visits(List.of(visit));
        Mockito
            .when(visitsServiceClient.getVisitsForPets(Collections.singletonList(cat.id())))
            .thenReturn(Mono.just(visits));

        client.get()
            .uri("/api/gateway/owners/1")
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.visitsUnavailable").isEqualTo(false)
            .jsonPath("$.pets[0].name").isEqualTo("Garfield")
            .jsonPath("$.pets[0].visits[0].description").isEqualTo("First visit");
    }

    /**
     * Test Resilience4j fallback method
     */
    @Test
    void getOwnerDetails_withServiceError() {
        PetDetails cat = PetDetails.PetDetailsBuilder.aPetDetails()
            .id(20)
            .name("Garfield")
            .visits(new ArrayList<>())
            .build();
        OwnerDetails owner = OwnerDetails.OwnerDetailsBuilder.anOwnerDetails()
            .pets(List.of(cat))
            .build();
        Mockito
            .when(customersServiceClient.getOwner(1))
            .thenReturn(Mono.just(owner));

        Mockito
            .when(visitsServiceClient.getVisitsForPets(Collections.singletonList(cat.id())))
            .thenReturn(Mono.error(new ConnectException("Simulate error")));

        client.get()
            .uri("/api/gateway/owners/1")
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.visitsUnavailable").isEqualTo(true)
            .jsonPath("$.pets[0].name").isEqualTo("Garfield")
            .jsonPath("$.pets[0].visits").isEmpty();
    }

    @Test
    void getOwnerDetails_withNoVisitsDoesNotSignalDegradation() {
        stubOwner();
        Mockito.when(visitsServiceClient.getVisitsForPets(List.of(20)))
            .thenReturn(Mono.just(new Visits(List.of())));

        client.get().uri("/api/gateway/owners/1").exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.visitsUnavailable").isEqualTo(false)
            .jsonPath("$.pets[0].visits").isEmpty();
    }

    @Test
    void getOwnerDetails_withEmptyVisitsResponseSignalsDegradation() {
        stubOwner();
        Mockito.when(visitsServiceClient.getVisitsForPets(List.of(20))).thenReturn(Mono.empty());

        client.get().uri("/api/gateway/owners/1").exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.visitsUnavailable").isEqualTo(true)
            .jsonPath("$.pets[0].name").isEqualTo("Garfield");
    }

    @Test
    void getOwnerDetails_withMissingOwnerReturnsNotFound() {
        Mockito.when(customersServiceClient.getOwner(1))
            .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "Owner 1 not found")));

        client.get().uri("/api/gateway/owners/1").exchange().expectStatus().isNotFound();
        Mockito.verifyNoInteractions(visitsServiceClient);
    }

    @Test
    void getOwnerDetails_withUnavailableCustomersReturnsServiceUnavailable() {
        Mockito.when(customersServiceClient.getOwner(1))
            .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "Customers service is currently unavailable.")));

        client.get().uri("/api/gateway/owners/1").exchange()
            .expectStatus().isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        Mockito.verifyNoInteractions(visitsServiceClient);
    }

    private void stubOwner() {
        PetDetails cat = PetDetails.PetDetailsBuilder.aPetDetails()
            .id(20).name("Garfield").visits(new ArrayList<>()).build();
        OwnerDetails owner = OwnerDetails.OwnerDetailsBuilder.anOwnerDetails().pets(List.of(cat)).build();
        Mockito.when(customersServiceClient.getOwner(1)).thenReturn(Mono.just(owner));
    }
}
