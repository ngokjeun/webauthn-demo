package com.example.webauthndemo.controller;

import com.example.webauthndemo.model.AppUser;
import com.example.webauthndemo.model.StoredCredential;
import com.example.webauthndemo.storage.InMemoryUserStorage;
import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.RegistrationFailedException;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;
import java.util.Map;

@RestController
@RequestMapping("/api/register")
public class RegistrationController {

    private static final String SESSION_PENDING_OPTIONS = "pendingRegistrationOptions";
    private static final String SESSION_PENDING_USERNAME = "pendingRegistrationUsername";
    private static final String SESSION_PENDING_DISPLAY_NAME = "pendingRegistrationDisplayName";

    private final RelyingParty relyingParty;
    private final InMemoryUserStorage userStorage;
    private final SecureRandom random = new SecureRandom();

    public RegistrationController(RelyingParty relyingParty, InMemoryUserStorage userStorage) {
        this.relyingParty = relyingParty;
        this.userStorage = userStorage;
    }

    @PostMapping("/start")
    public ResponseEntity<String> start(@RequestBody Map<String, String> body, HttpSession session) {
        String username = body.getOrDefault("username", "").trim();
        String displayName = body.getOrDefault("displayName", "").trim();
        if (username.isEmpty()) {
            return ResponseEntity.badRequest().body("{\"error\":\"username is required\"}");
        }
        if (displayName.isEmpty()) {
            displayName = username;
        }

        String loggedInUser = (String) session.getAttribute("username");
        UserIdentity userIdentity;

        if (loggedInUser != null && loggedInUser.equalsIgnoreCase(username)) {
            AppUser existing = userStorage.getUser(username)
                    .orElseThrow(() -> new IllegalStateException("logged-in user disappeared"));
            userIdentity = UserIdentity.builder()
                    .name(existing.getUsername())
                    .displayName(existing.getDisplayName())
                    .id(existing.getUserHandle())
                    .build();
        } else {
            if (userStorage.userExists(username)) {
                return ResponseEntity.status(409).body("{\"error\":\"username already registered\"}");
            }
            byte[] handleBytes = new byte[32];
            random.nextBytes(handleBytes);
            userIdentity = UserIdentity.builder()
                    .name(username)
                    .displayName(displayName)
                    .id(new ByteArray(handleBytes))
                    .build();
        }

        PublicKeyCredentialCreationOptions options = relyingParty.startRegistration(
                StartRegistrationOptions.builder()
                        .user(userIdentity)
                        .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                                .residentKey(ResidentKeyRequirement.PREFERRED)
                                .userVerification(UserVerificationRequirement.PREFERRED)
                                .build())
                        .build());

        session.setAttribute(SESSION_PENDING_OPTIONS, options);
        session.setAttribute(SESSION_PENDING_USERNAME, userIdentity.getName());
        session.setAttribute(SESSION_PENDING_DISPLAY_NAME, userIdentity.getDisplayName());

        try {
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
                    .body(options.toCredentialsCreateJson());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("{\"error\":\"failed to serialize options\"}");
        }
    }

    @PostMapping("/finish")
    public ResponseEntity<String> finish(@RequestBody JsonNode body, HttpSession session) {
        PublicKeyCredentialCreationOptions options =
                (PublicKeyCredentialCreationOptions) session.getAttribute(SESSION_PENDING_OPTIONS);
        String username = (String) session.getAttribute(SESSION_PENDING_USERNAME);
        String displayName = (String) session.getAttribute(SESSION_PENDING_DISPLAY_NAME);

        if (options == null || username == null) {
            return ResponseEntity.badRequest().body("{\"error\":\"no pending registration for this session\"}");
        }

        try {
            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc =
                    PublicKeyCredential.parseRegistrationResponseJson(body.toString());

            RegistrationResult result = relyingParty.finishRegistration(
                    FinishRegistrationOptions.builder()
                            .request(options)
                            .response(pkc)
                            .build());

            AppUser user = userStorage.getUser(username)
                    .orElseGet(() -> userStorage.createUser(username, displayName, options.getUser().getId()));

            StoredCredential credential = new StoredCredential(
                    result.getKeyId().getId(),
                    options.getUser().getId(),
                    result.getPublicKeyCose(),
                    result.getSignatureCount(),
                    "Passkey " + (user.getCredentials().size() + 1));
            userStorage.addCredential(user, credential);

            session.removeAttribute(SESSION_PENDING_OPTIONS);
            session.removeAttribute(SESSION_PENDING_USERNAME);
            session.removeAttribute(SESSION_PENDING_DISPLAY_NAME);
            session.setAttribute("username", user.getUsername());

            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
                    .body("{\"username\":\"" + user.getUsername() + "\"}");
        } catch (RegistrationFailedException e) {
            return ResponseEntity.badRequest().body("{\"error\":\"registration failed: " + e.getMessage() + "\"}");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("{\"error\":\"" + e.getMessage() + "\"}");
        }
    }
}
