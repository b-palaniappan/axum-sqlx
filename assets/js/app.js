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

  fetch('http://localhost:3000/passkey/register/start', {
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
      fetch('http://localhost:3000/passkey/register/finish', {
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

  fetch('http://localhost:3000/passkey/login/start', {
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
      fetch('http://localhost:3000/passkey/login/finish', {
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
            userHandle: Base64.fromUint8Array(new Uint8Array(assertion.response.userHandle), true),
          },
        })
      }).then(res => {
        showToaster(res.ok ? "Successfully logged in!" : "Error whilst logging in!", res.ok ? 'success' : 'error');
        // Clear input field after successful login
        if (res.ok) {
          document.getElementById('signinEmail').value = '';
        }
      });
    });
}
