package com.example.webauthndemo.controller;

import com.example.webauthndemo.model.AppUser;
import com.example.webauthndemo.model.StoredCredential;
import com.example.webauthndemo.storage.InMemoryUserStorage;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.Base64UrlException;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api")
public class SettingsController {

    private final InMemoryUserStorage userStorage;

    public SettingsController(InMemoryUserStorage userStorage) {
        this.userStorage = userStorage;
    }

    private Optional<AppUser> currentUser(HttpSession session) {
        String username = (String) session.getAttribute("username");
        if (username == null) {
            return Optional.empty();
        }
        return userStorage.getUser(username);
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(HttpSession session) {
        Optional<AppUser> user = currentUser(session);
        if (user.isEmpty()) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(userSummary(user.get()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpSession session) {
        session.invalidate();
        return ResponseEntity.ok().build();
    }

    @GetMapping("/settings/credentials")
    public ResponseEntity<?> listCredentials(HttpSession session) {
        Optional<AppUser> user = currentUser(session);
        if (user.isEmpty()) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(credentialSummaries(user.get()));
    }

    @PutMapping("/settings/credentials/{credentialId}")
    public ResponseEntity<?> renameCredential(
            @PathVariable String credentialId,
            @RequestBody Map<String, String> body,
            HttpSession session) {
        Optional<AppUser> userOpt = currentUser(session);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(401).build();
        }
        String nickname = body.getOrDefault("nickname", "").trim();
        if (nickname.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "nickname is required"));
        }
        ByteArray id;
        try {
            id = ByteArray.fromBase64Url(credentialId);
        } catch (Base64UrlException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid credential id"));
        }
        for (StoredCredential c : userOpt.get().getCredentials()) {
            if (c.getCredentialId().equals(id)) {
                c.setNickname(nickname);
                return ResponseEntity.ok(credentialSummaries(userOpt.get()));
            }
        }
        return ResponseEntity.status(404).body(Map.of("error", "credential not found"));
    }

    @DeleteMapping("/settings/credentials/{credentialId}")
    public ResponseEntity<?> deleteCredential(@PathVariable String credentialId, HttpSession session) {
        Optional<AppUser> userOpt = currentUser(session);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(401).build();
        }
        AppUser user = userOpt.get();
        if (user.getCredentials().size() <= 1) {
            return ResponseEntity.status(400).body(Map.of("error", "cannot remove your last passkey"));
        }
        ByteArray id;
        try {
            id = ByteArray.fromBase64Url(credentialId);
        } catch (Base64UrlException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid credential id"));
        }
        boolean removed = userStorage.removeCredential(user, id);
        if (!removed) {
            return ResponseEntity.status(404).body(Map.of("error", "credential not found"));
        }
        return ResponseEntity.ok(credentialSummaries(user));
    }

    @PutMapping("/settings/profile")
    public ResponseEntity<?> updateProfile(@RequestBody Map<String, String> body, HttpSession session) {
        Optional<AppUser> userOpt = currentUser(session);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(401).build();
        }
        String displayName = body.getOrDefault("displayName", "").trim();
        if (displayName.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "displayName is required"));
        }
        userOpt.get().setDisplayName(displayName);
        return ResponseEntity.ok(userSummary(userOpt.get()));
    }

    private Map<String, Object> userSummary(AppUser user) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("username", user.getUsername());
        map.put("displayName", user.getDisplayName());
        map.put("credentialCount", user.getCredentials().size());
        return map;
    }

    private List<Map<String, Object>> credentialSummaries(AppUser user) {
        DateTimeFormatter fmt = DateTimeFormatter.ISO_INSTANT;
        return user.getCredentials().stream()
                .map(c -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", c.getCredentialId().getBase64Url());
                    m.put("nickname", c.getNickname());
                    m.put("signatureCount", c.getSignatureCount());
                    m.put("createdAt", fmt.format(c.getCreatedAt()));
                    return m;
                })
                .toList();
    }
}
