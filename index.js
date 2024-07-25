import { Router } from 'itty-router';
const router = Router();
import { DOMParser, XMLSerializer } from '@xmldom/xmldom';

// Helper function to proxy request to Auth0
async function proxyRequestToAuth0(request, url) {
    try {
      // Ensure the URL is modified correctly
      url.hostname = AUTH0_HOST_NAME;
  
      // Create a new request with the same method and headers as the original request
      const newRequest = new Request(url.toString(), {
        method: request.method,
        headers: new Headers(request.headers),
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : null,
      });
  
      // Set additional headers
      newRequest.headers.set("Host", AUTH0_HOST_NAME);
      newRequest.headers.set("cname-api-key", CNAME_API_KEY);
  
      const trueClientIp = request.headers.get("CF-Connecting-IP");
      if (trueClientIp) {
        newRequest.headers.set("true-client-ip", trueClientIp);
      }
  
      let xForwardedFor = request.headers.get("X-Forwarded-For");
      if (xForwardedFor) {
        xForwardedFor += `, ${trueClientIp}`;
      } else {
        xForwardedFor = trueClientIp;
      }
      newRequest.headers.set("X-Forwarded-For", xForwardedFor);
  
      // Log the details of the new request
      console.log(`Proxying request to: ${url.toString()}`);
      console.log(`Headers: ${JSON.stringify([...newRequest.headers])}`);
  
      const response = await fetch(newRequest);
  
      // Log the response status for debugging
      console.log(`Received response with status: ${response.status}`);
  
      return response;
    } catch (error) {
      console.error(`Error in proxyRequestToAuth0: ${error.message}`);
      return new Response(`Error in proxying request: ${error.message}`, { status: 500 });
    }
  }
  

const PRIVATE_KEY = ENCRYPTION.PRIVATE_KEY;
const PUBLIC_KEY_SP = ENCRYPTION.PUBLIC_KEY;

function pemToArrayBuffer(pem) {
  const b64Lines = pem.replace(/(-----(BEGIN|END) (.*)-----|\s)/g, "");
  const b64 = b64Lines.replace(/(.{64})/g, "$1\n");
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

// Helper function to decrypt the key
async function decryptKey(encryptedKeyBase64, privateKey) {
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(privateKey),
    {
      name: "RSA-OAEP",
      hash: { name: "SHA-256" }
    },
    true,
    ["decrypt"]
  );

  const encryptedKey = Uint8Array.from(atob(encryptedKeyBase64), c => c.charCodeAt(0));
  const decryptedKey = await crypto.subtle.decrypt(
    {
      name: "RSA-OAEP"
    },
    cryptoKey,
    encryptedKey
  );
  return new Uint8Array(decryptedKey);
}

// Helper function to encrypt the key using SHA-1
async function encryptKeyWithSha1(aesKey, publicKeySP) {
  const cryptoKey = await crypto.subtle.importKey(
    "spki",
    pemToArrayBuffer(publicKeySP),
    {
      name: "RSA-OAEP",
      hash: { name: "SHA-1" }
    },
    true,
    ["encrypt"]
  );

  const encryptedKey = await crypto.subtle.encrypt(
    {
      name: "RSA-OAEP"
    },
    cryptoKey,
    aesKey
  );
  return btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedKey)));
}

// Helper function to proxy request to Auth0
async function proxyRequestToAuth0ModifiedBody(request, url, modifiedBody) {
    try {
      // Ensure the URL is modified correctly
      url.hostname = AUTH0_HOST_NAME;
  
      // Create a new request with the modified body
      const newRequest = new Request(url.toString(), {
        method: 'POST',
        headers: new Headers(request.headers),
        body: modifiedBody,
      });
  
      // Set additional headers
      newRequest.headers.set("Host", AUTH0_HOST_NAME);
      newRequest.headers.set("cname-api-key", CNAME_API_KEY);
  
      const trueClientIp = request.headers.get("CF-Connecting-IP");
      if (trueClientIp) {
        newRequest.headers.set("true-client-ip", trueClientIp);
      }
  
      let xForwardedFor = request.headers.get("X-Forwarded-For");
      if (xForwardedFor) {
        xForwardedFor += `, ${trueClientIp}`;
      } else {
        xForwardedFor = trueClientIp;
      }
      newRequest.headers.set("X-Forwarded-For", xForwardedFor);
  
      // Log the details of the new request
      console.log(`Proxying request to: ${url.toString()}`);
      console.log(`Headers: ${JSON.stringify([...newRequest.headers])}`);
      console.log(`Body: ${modifiedBody}`);
  
      const response = await fetch(newRequest);
  
      // Log the response status for debugging
      console.log(`Received response with status: ${response.status}`);
  
      return response;
    } catch (error) {
      console.error(`Error in proxyRequestToAuth0ModifiedBody: ${error.message}`);
      return new Response(`Error in proxying request: ${error.message}`, { status: 500 });
    }
  }

router.post('/login/callback', async request => {
  console.log("in POST /login/callback");
  const { searchParams } = new URL(request.url);

  if (searchParams.get('connection') === 'local') {
    console.log("in /login/callback, conn=local");
    const formData = await request.formData();
    const samlResponse = formData.get('SAMLResponse');

    if (samlResponse) {
      const samlResponseXml = atob(samlResponse);
      const parser = new DOMParser();
      const doc = parser.parseFromString(samlResponseXml, 'application/xml');

      const encryptedKeys = doc.getElementsByTagName('xenc:EncryptedKey');
      if (encryptedKeys.length > 0) {
        const encryptedKey = encryptedKeys[0];
        const cipherValues = encryptedKey.getElementsByTagName('xenc:CipherValue');
        if (cipherValues.length > 0) {
          const cipherValue = cipherValues[0].textContent.trim();
          const digestMethodElement = encryptedKey.getElementsByTagName('ds:DigestMethod')[0];
          const digestMethod = digestMethodElement.getAttribute('Algorithm');

          if (digestMethod === 'http://www.w3.org/2001/04/xmlenc#sha256') {
            console.log(digestMethod);
            const privateKey = PRIVATE_KEY.replace(/(-----(BEGIN|END) PRIVATE KEY-----|\n)/g, '').trim();
            const publicKeySP = PUBLIC_KEY_SP.replace(/(-----(BEGIN|END) PUBLIC KEY-----|\n)/g, '').trim();

            try {
              const decryptedKey = await decryptKey(cipherValue, privateKey);
              const reEncryptedKey = await encryptKeyWithSha1(decryptedKey, publicKeySP);

              // Update the existing cipher value node
              cipherValues[0].textContent = reEncryptedKey;

              // Update the digest method
              digestMethodElement.setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha1');

              // Serialize the updated document back to a string
              const updatedSamlResponse = new XMLSerializer().serializeToString(doc);
              const updatedSamlResponseBase64 = btoa(updatedSamlResponse);

              formData.set('SAMLResponse', updatedSamlResponseBase64);
              
              const body = new URLSearchParams(formData).toString();
              console.log(body);
              // Proxy the request to Auth0
              const url = new URL(request.url);
              return await proxyRequestToAuth0ModifiedBody(request, url, body);

            } catch (error) {
              console.error(`Decryption failed: ${error.message}`);
              return new Response(`Decryption failed: ${error.message}`, { status: 500 });
            }
          } else {
            const body = new URLSearchParams(formData).toString();
            // Proxy the request to Auth0
            const url = new URL(request.url);
            return await proxyRequestToAuth0ModifiedBody(request, url, body);
          }
        } else {
          console.log('No xenc:CipherValue found inside xenc:EncryptedKey');
        }
      } else {
        console.log('No xenc:EncryptedKey found');
      }
    } else {
      const body = new URLSearchParams(formData).toString();
      // Proxy the request to Auth0
      const url = new URL(request.url);
      return await proxyRequestToAuth0ModifiedBody(request, url, body);
    }
  } else {
    const url = new URL(request.url);
    return await proxyRequestToAuth0(request, url);
  }
});

// Default route
router.all('*', async (request) => {
  try {
    const url = new URL(request.url);
    url.hostname = AUTH0_HOST_NAME;

    const newRequest = new Request(url, request, { headers: new Headers(request.headers) });
    newRequest.headers.set("Host", AUTH0_HOST_NAME);
    newRequest.headers.set("cname-api-key", CNAME_API_KEY);

    const trueClientIp = request.headers.get("CF-Connecting-IP");
    newRequest.headers.set("true-client-ip", trueClientIp);

    let xForwardedFor = request.headers.get("X-Forwarded-For");
    if (xForwardedFor) {
      xForwardedFor += `, ${trueClientIp}`;
    } else {
      xForwardedFor = trueClientIp;
    }
    newRequest.headers.set("X-Forwarded-For", xForwardedFor);

    console.log(`Proxying request to: ${url.toString()}`);
    console.log(`Headers: ${JSON.stringify([...newRequest.headers])}`);


    return await fetch(newRequest);
  } catch (error) {
    console.error(`Error in default route:   ${error.message}`);
    return new Response(`Error in processing request: ${error.message}`, { status: 500 });
  }
});

// Attach router to the fetch event
addEventListener('fetch', event => {
  event.respondWith(router.handle(event.request).catch(err => {
    console.error(`Unhandled error: ${err.message}`);
    return new Response(`Internal Server Error: ${err.message}`, { status: 500 });
  }));
});
