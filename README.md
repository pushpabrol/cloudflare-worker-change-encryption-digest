# README

## Overview

This project provides a serverless solution using Cloudflare Workers to handle requests, specifically proxying them to Auth0 with additional processing for SAML responses. The code uses the `itty-router` for routing and the `xmldom` library for XML manipulation.

## Features

- **Proxy Requests to Auth0**: Forward incoming requests to Auth0, modifying the headers as needed.
- **Decrypt and Re-Encrypt Keys**: Handle SAML responses by decrypting and re-encrypting keys using specified algorithms.
- **Routing**: Utilize the `itty-router` to manage different routes and handle incoming requests accordingly.

## Setup

### Dependencies

- `itty-router`: Lightweight router for handling request routing.
- `xmldom`: XML parser and serializer for handling SAML responses.

### Environment Variables

Ensure the following environment variables are set:

- `AUTH0_HOST_NAME`: The hostname for Auth0.
- `CNAME_API_KEY`: The API key for the CNAME.
- `ENCRYPTION.PRIVATE_KEY`: The private key for decryption.
- `ENCRYPTION.PUBLIC_KEY`: The public key for encryption.

## Code Explanation

### Proxying Requests to Auth0

The function `proxyRequestToAuth0` modifies the URL and headers of incoming requests before forwarding them to Auth0. It also logs request details and handles errors.

### PEM to ArrayBuffer Conversion

The function `pemToArrayBuffer` converts a PEM formatted key to an ArrayBuffer, which is required for cryptographic operations.

### Key Decryption and Encryption

- `decryptKey`: Decrypts an encrypted key using the RSA-OAEP algorithm with SHA-256.
- `encryptKeyWithSha1`: Encrypts a key using the RSA-OAEP algorithm with SHA-1.

### Proxying Modified Requests

The function `proxyRequestToAuth0ModifiedBody` is similar to `proxyRequestToAuth0` but allows for a modified request body, which is necessary for handling modified SAML responses.

### Handling SAML Responses

The route handler for `/login/callback` processes SAML responses. It decrypts and re-encrypts keys if necessary, modifies the XML document, and forwards the modified request to Auth0.

### Default Route

The default route handles all other requests, forwarding them to Auth0 with the necessary modifications to headers.

### Event Listener

An event listener is added to handle fetch events, directing them to the router for processing.

## Usage

Deploy this code as an Akamai EdgeWorker to handle requests, particularly for processing and forwarding SAML responses to Auth0.

### Example

To handle a POST request to `/login/callback`, the code will:
1. Parse the SAML response.
2. Decrypt and re-encrypt keys if required.
3. Modify the XML document accordingly.
4. Forward the modified request to Auth0.

## Error Handling

Errors encountered during request processing, decryption, or encryption are logged, and appropriate error responses are returned.

## Logging

The code includes logging for request details, modifications, and errors to aid in debugging and monitoring.
