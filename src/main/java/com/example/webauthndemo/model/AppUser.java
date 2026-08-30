package com.example.webauthndemo.model;

import com.yubico.webauthn.data.ByteArray;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class AppUser {
    private final String username;
    private final ByteArray userHandle;
    private volatile String displayName;
    private final List<StoredCredential> credentials = new CopyOnWriteArrayList<>();

    public AppUser(String username, String displayName, ByteArray userHandle) {
        this.username = username;
        this.displayName = displayName;
        this.userHandle = userHandle;
    }

    public String getUsername() {
        return username;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public ByteArray getUserHandle() {
        return userHandle;
    }

    public List<StoredCredential> getCredentials() {
        return credentials;
    }
}
