package com.example.webauthndemo.controller;

import com.example.webauthndemo.model.AppUser;
import com.example.webauthndemo.storage.InMemoryUserStorage;
import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.exception.AssertionFailedException;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/login")
public class AuthenticationController {

    private static final String SESSION_PENDING_ASSERTION = "pendingAssertionRequest";

    private final RelyingParty relyingParty;
    private final InMemoryUserStorage userStorage;

    public AuthenticationController(RelyingParty relyingParty, InMemoryUserStorage userStorage) {
        this.relyingParty = relyingParty;
        this.userStorage = userStorage;
    }

    @PostMapping("/start")
    public ResponseEntity<String> start(@RequestBody(required = false) Map<String, String> body, HttpSession session) {
        String username = body == null ? null : body.get("username");

        var builder = StartAssertionOptions.builder();
        if (username != null && !username.isBlank()) {
            builder.username(username);
        }

        AssertionRequest request = relyingParty.startAssertion(builder.build());
        session.setAttribute(SESSION_PENDING_ASSERTION, request);

        try {
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
                    .body(request.toCredentialsGetJson());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("{\"error\":\"failed to serialize options\"}");
        }
    }

    @PostMapping("/finish")
    public ResponseEntity<String> finish(@RequestBody JsonNode body, HttpSession session) {
        AssertionRequest request = (AssertionRequest) session.getAttribute(SESSION_PENDING_ASSERTION);
        if (request == null) {
            return ResponseEntity.badRequest().body("{\"error\":\"no pending login for this session\"}");
        }

        try {
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc =
                    PublicKeyCredential.parseAssertionResponseJson(body.toString());

            AssertionResult result = relyingParty.finishAssertion(
                    FinishAssertionOptions.builder()
                            .request(request)
                            .response(pkc)
                            .build());

            session.removeAttribute(SESSION_PENDING_ASSERTION);

            if (!result.isSuccess()) {
                return ResponseEntity.status(401).body("{\"error\":\"authentication failed\"}");
            }

            String username = result.getUsername();
            Optional<AppUser> user = userStorage.getUser(username);
            user.ifPresent(u -> u.getCredentials().stream()
                    .filter(c -> c.getCredentialId().equals(result.getCredential().getCredentialId()))
                    .findFirst()
                    .ifPresent(c -> c.setSignatureCount(result.getSignatureCount())));

            session.setAttribute("username", username);

            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
                    .body("{\"username\":\"" + username + "\"}");
        } catch (AssertionFailedException e) {
            return ResponseEntity.status(401).body("{\"error\":\"authentication failed: " + e.getMessage() + "\"}");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("{\"error\":\"" + e.getMessage() + "\"}");
        }
    }
}
