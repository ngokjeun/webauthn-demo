// Minimal helpers to bridge the browser WebAuthn API with the
// JSON shape expected/produced by the Yubico java-webauthn-server library.

function base64urlToBuffer(base64url) {
    const padding = "=".repeat((4 - (base64url.length % 4)) % 4);
    const base64 = (base64url + padding).replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(base64);
    const buffer = new ArrayBuffer(raw.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < raw.length; i++) {
        bytes[i] = raw.charCodeAt(i);
    }
    return buffer;
}

function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = "";
    for (const b of bytes) {
        str += String.fromCharCode(b);
    }
    return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function postJson(url, body) {
    const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let data = null;
    try {
        data = text ? JSON.parse(text) : null;
    } catch (e) {
        data = null;
    }
    if (!res.ok) {
        const message = (data && data.error) || `Request failed (${res.status})`;
        throw new Error(message);
    }
    return data;
}

function optionsFromServer(json) {
    // The server's options JSON encodes challenge / ids as base64url strings.
    // Deep-clone while converting known binary fields into ArrayBuffers.
    const options = JSON.parse(JSON.stringify(json));
    options.challenge = base64urlToBuffer(json.challenge);

    if (options.user) {
        options.user.id = base64urlToBuffer(json.user.id);
    }
    if (Array.isArray(options.excludeCredentials)) {
        options.excludeCredentials = options.excludeCredentials.map((c) => ({
            ...c,
            id: base64urlToBuffer(c.id),
        }));
    }
    if (Array.isArray(options.allowCredentials)) {
        options.allowCredentials = options.allowCredentials.map((c) => ({
            ...c,
            id: base64urlToBuffer(c.id),
        }));
    }
    return options;
}

function credentialToJson(credential) {
    const response = credential.response;
    const base = {
        type: credential.type,
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        clientExtensionResults: credential.getClientExtensionResults
            ? credential.getClientExtensionResults()
            : {},
    };
    if (credential.authenticatorAttachment) {
        base.authenticatorAttachment = credential.authenticatorAttachment;
    }

    if (response.attestationObject) {
        base.response = {
            attestationObject: bufferToBase64url(response.attestationObject),
            clientDataJSON: bufferToBase64url(response.clientDataJSON),
            transports: response.getTransports ? response.getTransports() : [],
        };
    } else {
        base.response = {
            authenticatorData: bufferToBase64url(response.authenticatorData),
            clientDataJSON: bufferToBase64url(response.clientDataJSON),
            signature: bufferToBase64url(response.signature),
        };
        if (response.userHandle) {
            base.response.userHandle = bufferToBase64url(response.userHandle);
        }
    }
    return base;
}

async function registerPasskey(username, displayName) {
    if (!window.PublicKeyCredential) {
        throw new Error("This browser does not support WebAuthn / passkeys.");
    }
    const creationOptionsJson = await postJson("/api/register/start", { username, displayName });
    const publicKey = optionsFromServer(creationOptionsJson.publicKey);

    const credential = await navigator.credentials.create({ publicKey });
    if (!credential) {
        throw new Error("Passkey creation was cancelled.");
    }

    return postJson("/api/register/finish", credentialToJson(credential));
}

async function loginWithPasskey(username) {
    if (!window.PublicKeyCredential) {
        throw new Error("This browser does not support WebAuthn / passkeys.");
    }
    const requestOptionsJson = await postJson("/api/login/start", { username: username || "" });
    const publicKey = optionsFromServer(requestOptionsJson.publicKey);

    const credential = await navigator.credentials.get({ publicKey });
    if (!credential) {
        throw new Error("Passkey sign-in was cancelled.");
    }

    return postJson("/api/login/finish", credentialToJson(credential));
}

async function getCurrentUser() {
    const res = await fetch("/api/me", { credentials: "same-origin" });
    if (!res.ok) {
        return null;
    }
    return res.json();
}

async function logout() {
    await fetch("/api/logout", { method: "POST", credentials: "same-origin" });
}
