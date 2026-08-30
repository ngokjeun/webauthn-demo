package com.example.webauthndemo.storage;

import com.example.webauthndemo.model.AppUser;
import com.example.webauthndemo.model.StoredCredential;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Pure in-memory store for demo purposes only. All data is lost on restart.
 */
@Component
public class InMemoryUserStorage implements CredentialRepository {

    private final Map<String, AppUser> usersByName = new ConcurrentHashMap<>();
    private final Map<ByteArray, AppUser> usersByHandle = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();

    public AppUser createUser(String username, String displayName) {
        byte[] handleBytes = new byte[32];
        random.nextBytes(handleBytes);
        return createUser(username, displayName, new ByteArray(handleBytes));
    }

    public AppUser createUser(String username, String displayName, ByteArray userHandle) {
        String key = username.toLowerCase();
        AppUser user = new AppUser(username, displayName, userHandle);
        usersByName.put(key, user);
        usersByHandle.put(user.getUserHandle(), user);
        return user;
    }

    public Optional<AppUser> getUser(String username) {
        return Optional.ofNullable(usersByName.get(username.toLowerCase()));
    }

    public boolean userExists(String username) {
        return usersByName.containsKey(username.toLowerCase());
    }

    public void addCredential(AppUser user, StoredCredential credential) {
        user.getCredentials().add(credential);
    }

    public boolean removeCredential(AppUser user, ByteArray credentialId) {
        return user.getCredentials().removeIf(c -> c.getCredentialId().equals(credentialId));
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return getUser(username)
                .map(u -> u.getCredentials().stream()
                        .map(c -> PublicKeyCredentialDescriptor.builder().id(c.getCredentialId()).build())
                        .collect(Collectors.toSet()))
                .orElseGet(HashSet::new);
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return getUser(username).map(AppUser::getUserHandle);
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return Optional.ofNullable(usersByHandle.get(userHandle)).map(AppUser::getUsername);
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        AppUser user = usersByHandle.get(userHandle);
        if (user == null) {
            return Optional.empty();
        }
        return user.getCredentials().stream()
                .filter(c -> c.getCredentialId().equals(credentialId))
                .findFirst()
                .map(c -> RegisteredCredential.builder()
                        .credentialId(c.getCredentialId())
                        .userHandle(c.getUserHandle())
                        .publicKeyCose(c.getPublicKeyCose())
                        .signatureCount(c.getSignatureCount())
                        .build());
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        Set<RegisteredCredential> result = new HashSet<>();
        for (AppUser user : usersByName.values()) {
            for (StoredCredential c : user.getCredentials()) {
                if (c.getCredentialId().equals(credentialId)) {
                    result.add(RegisteredCredential.builder()
                            .credentialId(c.getCredentialId())
                            .userHandle(c.getUserHandle())
                            .publicKeyCose(c.getPublicKeyCose())
                            .signatureCount(c.getSignatureCount())
                            .build());
                }
            }
        }
        return result;
    }
}
