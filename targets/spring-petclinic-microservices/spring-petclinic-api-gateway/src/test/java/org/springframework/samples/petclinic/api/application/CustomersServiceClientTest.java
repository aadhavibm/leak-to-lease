package org.springframework.samples.petclinic.api.application;

import java.net.ConnectException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CustomersServiceClientTest {

    @Test
    void returnsOwnerWithoutCallingADownstreamService() {
        CustomersServiceClient client = client(Mono.just(ClientResponse.create(HttpStatus.OK)
            .header("Content-Type", "application/json")
            .body("""
                {"id":1,"firstName":"George","pets":[]}
                """).build()));

        var owner = client.getOwner(1).block();
        assertThat(owner.firstName()).isEqualTo("George");
        assertThat(owner.visitsUnavailable()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 404, 429})
    void preservesCustomerClientErrorStatus(int status) {
        CustomersServiceClient client = client(Mono.just(ClientResponse.create(HttpStatus.valueOf(status)).build()));

        assertThatThrownBy(() -> client.getOwner(1).block())
            .isInstanceOfSatisfying(ResponseStatusException.class,
                error -> assertThat(error.getStatusCode().value()).isEqualTo(status));
    }

    @ParameterizedTest
    @ValueSource(ints = {500, 503})
    void translatesCustomerServerErrorsToServiceUnavailable(int status) {
        CustomersServiceClient client = client(Mono.just(ClientResponse.create(HttpStatus.valueOf(status)).build()));

        assertServiceUnavailable(client);
    }

    @Test
    void translatesConnectionErrorsToServiceUnavailable() {
        assertServiceUnavailable(client(Mono.error(new ConnectException("Simulated connection failure"))));
    }

    @Test
    void rejectsEmptySuccessResponse() {
        assertServiceUnavailable(client(Mono.just(ClientResponse.create(HttpStatus.OK).build())));
    }

    @Test
    void rejectsInvalidSuccessResponse() {
        assertServiceUnavailable(client(Mono.just(ClientResponse.create(HttpStatus.OK)
            .header("Content-Type", "application/json").body("not JSON").build())));
    }

    private CustomersServiceClient client(Mono<ClientResponse> response) {
        return new CustomersServiceClient(WebClient.builder().exchangeFunction(request -> response));
    }

    private void assertServiceUnavailable(CustomersServiceClient client) {
        assertThatThrownBy(() -> client.getOwner(1).block())
            .isInstanceOfSatisfying(ResponseStatusException.class,
                error -> assertThat(error.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
    }
}
