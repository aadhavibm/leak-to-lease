package org.springframework.samples.petclinic.genai;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.memory.ChatMemory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.server.ResponseStatusException;

import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class PetclinicChatClientTest {

    private final ChatClient chatClient = mock(ChatClient.class, RETURNS_DEEP_STUBS);
    private MockMvc mvc;

    @BeforeEach
    void setup() {
        ChatClient.Builder builder = mock(ChatClient.Builder.class, RETURNS_SELF);
        when(builder.build()).thenReturn(chatClient);
        mvc = MockMvcBuilders.standaloneSetup(new PetclinicChatClient(builder,
            mock(ChatMemory.class), mock(PetclinicTools.class))).build();
    }

    @Test
    void returnsSuccessfulChatContent() throws Exception {
        when(chatClient.prompt().user("query").call().content()).thenReturn("Hello");

        mvc.perform(post("/chatclient").contentType(MediaType.TEXT_PLAIN).content("query"))
            .andExpect(status().isOk()).andExpect(content().string("Hello"));
    }

    @Test
    void propagatesUnavailableCustomerStatus() throws Exception {
        when(chatClient.prompt().user("query").call().content())
            .thenThrow(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Customers unavailable"));

        mvc.perform(post("/chatclient").contentType(MediaType.TEXT_PLAIN).content("query"))
            .andExpect(status().isServiceUnavailable());
    }

    @Test
    void propagatesWrappedUnavailableCustomerStatus() throws Exception {
        when(chatClient.prompt().user("query").call().content())
            .thenThrow(new IllegalStateException("Tool failed",
                new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Customers unavailable")));

        mvc.perform(post("/chatclient").contentType(MediaType.TEXT_PLAIN).content("query"))
            .andExpect(status().isServiceUnavailable());
    }

    @Test
    void preservesExistingChatFallbackForOtherErrors() throws Exception {
        when(chatClient.prompt().user("query").call().content()).thenThrow(new IllegalStateException("Chat failed"));

        mvc.perform(post("/chatclient").contentType(MediaType.TEXT_PLAIN).content("query"))
            .andExpect(status().isOk())
            .andExpect(content().string("Chat is currently unavailable. Please try again later."));
    }
}
