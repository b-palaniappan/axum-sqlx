
function register() {
  let username = document.getElementById('username').value;
  if (username === "") {
    alert("Please enter a username");
    return;
  }

  fetch('http://localhost:3000/passkey/register/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email: username,
      type: "passkey",
    })
  })
    .then(response => response.json())
    .then(credentialCreationOptions => {
      window.requestId = credentialCreationOptions.requestId;

      credentialCreationOptions.publicKey.challenge = Base64.toUint8Array(credentialCreationOptions.publicKey.challenge);
      credentialCreationOptions.publicKey.user.id = Base64.toUint8Array(credentialCreationOptions.publicKey.user.id);
      credentialCreationOptions.publicKey.excludeCredentials?.forEach(function (listItem) {
        listItem.id = Base64.toUint8Array(listItem.id)
      });

      return navigator.credentials.create({
        publicKey: credentialCreationOptions.publicKey
      });
    })
    .then((credential) => {
      fetch('http://localhost:3000/passkey/register/finish', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': window.requestId,
        },
        body: JSON.stringify({
          id: credential.id,
          rawId: Base64.fromUint8Array(new Uint8Array(credential.rawId), true),
          type: credential.type,
          response: {
            attestationObject: Base64.fromUint8Array(new Uint8Array(credential.response.attestationObject), true),
            clientDataJSON: Base64.fromUint8Array(new Uint8Array(credential.response.clientDataJSON), true),
          },
        })
      })
        .then((response) => {
          const flash_message = document.getElementById('flash_message');
          if (response.ok) {
            flash_message.innerHTML = "Successfully registered!";
            flash_message.className = "info";
          } else {
            flash_message.innerHTML = "Error whilst registering!";
            flash_message.className = "error";
          }
        });
    })
}

function login() {
  let username = document.getElementById('username').value;
  if (username === "") {
    alert("Please enter a username");
    return;
  }

  fetch('http://localhost:3000/passkey/login/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email: username,
      type: "passkey",
    })
  })
    .then(response => response.json())
    .then((credentialRequestOptions) => {
      window.requestId = credentialRequestOptions.requestId;

      credentialRequestOptions.publicKey.challenge = Base64.toUint8Array(credentialRequestOptions.publicKey.challenge);
      credentialRequestOptions.publicKey.allowCredentials?.forEach(function (listItem) {
        listItem.id = Base64.toUint8Array(listItem.id)
      });

      return navigator.credentials.get({
        publicKey: credentialRequestOptions.publicKey
      });
    })
    .then((assertion) => {
      fetch('http://localhost:3000/passkey/login/finish', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': window.requestId,
        },
        body: JSON.stringify({
          id: assertion.id,
          rawId: Base64.fromUint8Array(new Uint8Array(assertion.rawId), true),
          type: assertion.type,
          response: {
            authenticatorData: Base64.fromUint8Array(new Uint8Array(assertion.response.authenticatorData), true),
            clientDataJSON: Base64.fromUint8Array(new Uint8Array(assertion.response.clientDataJSON), true),
            signature: Base64.fromUint8Array(new Uint8Array(assertion.response.signature), true),
            userHandle: Base64.fromUint8Array(new Uint8Array(assertion.response.userHandle), true)
          },
        }),
      })
        .then((response) => {
          const flash_message = document.getElementById('flash_message');
          if (response.ok) {
            flash_message.innerHTML = "Successfully logged in!";
            flash_message.className = "info";
          } else {
            flash_message.innerHTML = "Error whilst logging in!";
            flash_message.className = "error";
          }
        });
    });
}
