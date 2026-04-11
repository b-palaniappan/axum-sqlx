function showToaster(message, type = 'success') {
  const toaster = document.createElement('div');
  toaster.className = `toaster ${type}`;
  toaster.innerHTML = `
    <span>${message}</span>
    <button class="toaster-close" aria-label="Close notification">×</button>
  `;
  document.body.appendChild(toaster);

  const closeToaster = () => {
    toaster.classList.remove('show');
    setTimeout(() => toaster.remove(), 300);
  };

  toaster.querySelector('.toaster-close').addEventListener('click', closeToaster);
  setTimeout(() => toaster.classList.add('show'), 10);
  setTimeout(closeToaster, 10000);
}

const API_BASE_URL = 'http://localhost:3000/passkey';
const ACCESS_TOKEN_COOKIE = 'accessToken';
const ACCESS_TOKEN_EXPIRY_COOKIE = 'accessTokenExpiresAt';
const USER_EMAIL_COOKIE = 'userEmail';

function setCookie(name, value, maxAgeSeconds) {
  const encodedValue = encodeURIComponent(value);
  const cookieParts = [`${name}=${encodedValue}`, 'Path=/', 'SameSite=Strict'];
  if (typeof maxAgeSeconds === 'number') {
    cookieParts.push(`Max-Age=${maxAgeSeconds}`);
  }
  document.cookie = cookieParts.join('; ');
}

function getCookie(name) {
  const prefix = `${name}=`;
  for (const part of document.cookie.split(';')) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) {
      return decodeURIComponent(trimmed.slice(prefix.length));
    }
  }
  return '';
}

function clearCookie(name) {
  document.cookie = `${name}=; Path=/; SameSite=Strict; Max-Age=0`;
}

function storeSession(accessToken, expiresIn, email) {
  setCookie(ACCESS_TOKEN_COOKIE, accessToken, expiresIn);
  setCookie(ACCESS_TOKEN_EXPIRY_COOKIE, String(Date.now() + (expiresIn * 1000)), expiresIn);
  if (email) {
    setCookie(USER_EMAIL_COOKIE, email, expiresIn);
  }
}

function clearSession() {
  clearCookie(ACCESS_TOKEN_COOKIE);
  clearCookie(ACCESS_TOKEN_EXPIRY_COOKIE);
  clearCookie(USER_EMAIL_COOKIE);
}

function isLoggedIn() {
  const accessToken = getCookie(ACCESS_TOKEN_COOKIE);
  const expiresAt = Number(getCookie(ACCESS_TOKEN_EXPIRY_COOKIE));

  if (!accessToken || !expiresAt) {
    return false;
  }

  if (Date.now() >= expiresAt) {
    clearSession();
    return false;
  }

  return true;
}

function redirectToWelcome() {
  globalThis.location.href = './welcome.html';
}

function redirectToLogin() {
  globalThis.location.href = './index.html';
}

globalThis.showTab = function(tabName, element) {
  for (const tab of document.querySelectorAll('.tab')) {
    tab.classList.remove('active');
  }
  for (const container of document.querySelectorAll('.form-container')) {
    container.classList.add('hidden');
    container.classList.remove('active');
  }

  element.classList.add('active');
  const targetContainer = document.getElementById(tabName);
  targetContainer.classList.add('active');
  targetContainer.classList.remove('hidden');

  const flashMessage = document.getElementById('flash_message');
  flashMessage.innerHTML = '';
  flashMessage.className = 'flash-message';
  flashMessage.style.display = 'none';

  // Clear all input fields when switching tabs
  for (const input of document.querySelectorAll('.input')) {
    input.value = '';
  }
};

function register() {
  const firstName = document.getElementById('firstName').value;
  const lastName = document.getElementById('lastName').value;
  const username = document.getElementById('signupEmail').value;

  if (!firstName || !lastName || !username) return alert("Please fill in all fields");

  fetch(`${API_BASE_URL}/register/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: username, firstName, lastName, type: "passkey" })
  })
    .then(res => res.json())
    .then(options => {
      globalThis.requestId = options.requestId;
      options.publicKey.challenge = Base64.toUint8Array(options.publicKey.challenge);
      options.publicKey.user.id = Base64.toUint8Array(options.publicKey.user.id);
      if (options.publicKey.excludeCredentials) {
        for (const item of options.publicKey.excludeCredentials) {
          item.id = Base64.toUint8Array(item.id);
        }
      }

      return navigator.credentials.create({ publicKey: options.publicKey });
    })
    .then(credential => {
      fetch(`${API_BASE_URL}/register/finish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Request-ID': globalThis.requestId },
        body: JSON.stringify({
          id: credential.id,
          rawId: Base64.fromUint8Array(new Uint8Array(credential.rawId), true),
          type: credential.type,
          response: {
            attestationObject: Base64.fromUint8Array(new Uint8Array(credential.response.attestationObject), true),
            clientDataJSON: Base64.fromUint8Array(new Uint8Array(credential.response.clientDataJSON), true),
          },
        })
      }).then(res => {
        showToaster(res.ok ? "Successfully registered!" : "Error whilst registering!", res.ok ? 'success' : 'error');
        // Clear input fields after successful registration
        if (res.ok) {
          document.getElementById('firstName').value = '';
          document.getElementById('lastName').value = '';
          document.getElementById('signupEmail').value = '';
        }
      });
    });
}

function login() {
  const username = document.getElementById('signinEmail').value;
  if (!username) return alert("Please enter a username");

  fetch(`${API_BASE_URL}/login/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: username, type: "passkey" })
  })
    .then(res => res.json())
    .then(options => {
      globalThis.requestId = options.requestId;
      options.publicKey.challenge = Base64.toUint8Array(options.publicKey.challenge);
      if (options.publicKey.allowCredentials) {
        for (const item of options.publicKey.allowCredentials) {
          item.id = Base64.toUint8Array(item.id);
        }
      }

      return navigator.credentials.get({ publicKey: options.publicKey });
    })
    .then(assertion => {
      return fetch(`${API_BASE_URL}/login/finish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Request-ID': globalThis.requestId },
        body: JSON.stringify({
          id: assertion.id,
          rawId: Base64.fromUint8Array(new Uint8Array(assertion.rawId), true),
          type: assertion.type,
          response: {
            authenticatorData: Base64.fromUint8Array(new Uint8Array(assertion.response.authenticatorData), true),
            clientDataJSON: Base64.fromUint8Array(new Uint8Array(assertion.response.clientDataJSON), true),
            signature: Base64.fromUint8Array(new Uint8Array(assertion.response.signature), true),
            userHandle: assertion.response.userHandle
              ? Base64.fromUint8Array(new Uint8Array(assertion.response.userHandle), true)
              : null,
          },
        })
      });
    })
    .then(async res => {
      if (!res.ok) {
        showToaster("Error whilst logging in!", 'error');
        return;
      }

      const payload = await res.json();
      if (!payload?.accessToken) {
        showToaster("Login succeeded but no access token was returned.", 'error');
        return;
      }

      storeSession(payload.accessToken, payload.expiresIn, username);
      document.getElementById('signinEmail').value = '';
      redirectToWelcome();
    })
    .catch(() => {
      showToaster("Error whilst logging in!", 'error');
    });
}

async function logout() {
  const accessToken = getCookie(ACCESS_TOKEN_COOKIE);

  try {
    await fetch(`${API_BASE_URL}/logout`, {
      method: 'DELETE',
      headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
      credentials: 'include',
    });
  } finally {
    clearSession();
    redirectToLogin();
  }
}

function initWelcomePage() {
  if (!isLoggedIn()) {
    redirectToLogin();
    return;
  }

  const welcomeEmail = document.getElementById('welcomeEmail');
  if (welcomeEmail) {
    welcomeEmail.textContent = getCookie(USER_EMAIL_COOKIE) || 'Authenticated user';
  }

  const logoutLink = document.getElementById('logoutLink');
  if (logoutLink) {
    logoutLink.addEventListener('click', event => {
      event.preventDefault();
      logout();
    });
  }
}

function initLoginPage() {
  if (isLoggedIn()) {
    redirectToWelcome();
  }
}

document.addEventListener('DOMContentLoaded', () => {
  if (document.body.dataset.page === 'welcome') {
    initWelcomePage();
    return;
  }

  initLoginPage();
});

globalThis.register = register;
globalThis.login = login;
