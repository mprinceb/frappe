# JWKS Testing Guide for Frappe OAuth2/OpenID Connect

This guide provides instructions for testing the JWKS (JSON Web Key Set) implementation in Frappe's OAuth2/OpenID Connect system.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Running Automated Tests](#running-automated-tests)
- [Manual Testing with Postman](#manual-testing-with-postman)
- [Step-by-Step Testing Guide](#step-by-step-testing-guide)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Before you begin testing, make sure you have the following:

1. A running Frappe instance
2. Administrator access to the Frappe instance
3. [Postman](https://www.postman.com/downloads/) installed for manual testing
4. An OAuth Client configured in your Frappe instance

### Setting up an OAuth Client for testing

1. Log in to your Frappe instance as an Administrator
2. Go to "Integrations" > "OAuth Client"
3. Click "New"
4. Fill in the following details:
   - App Name: `JWKS Test Client`
   - Client ID: (auto-generated)
   - Client Secret: (auto-generated or enter your own)
   - Skip Authorization: Check this box for easier testing
   - Grant Type: `Authorization Code`
   - Response Type: `Code`
   - Redirect URIs: `http://localhost`
   - Default Redirect URI: `http://localhost`
   - Scopes: `all openid email profile`
5. Save the client

### Enabling JWKS in OAuth Provider Settings

1. Go to "Integrations" > "OAuth Provider Settings"
2. Check "Enable JWKS for JWT Signing"
3. Save the settings

## Running Automated Tests

We've created a test suite that automatically tests the JWKS implementation. To run it:

```bash
# Navigate to your Frappe bench directory
cd /path/to/frappe-bench

# Run the specific JWKS test
bench --site your-site run-tests --module "frappe.tests.test_jwks"
```

The test will check:
- Key generation
- JWKS endpoint functionality
- OpenID configuration with JWKS
- Token signing with RS256
- Key rotation

## Manual Testing with Postman

For manual testing, you can use the provided Postman collection:

1. Download the [jwks_postman_collection.json](jwks_postman_collection.json) file
2. Open Postman
3. Click "Import" and select the downloaded file
4. Update the collection variables:
   - `base_url`: Your Frappe instance URL (e.g., `http://localhost:8000`)
   - `client_id`: Your OAuth Client ID
   - `client_secret`: Your OAuth Client Secret
   - `redirect_uri`: Your redirect URI (e.g., `http://localhost`)

## Step-by-Step Testing Guide

### 1. Verify OpenID Configuration

First, check if the OpenID Configuration includes JWKS information:

1. In Postman, run the "1. OpenID Configuration" request
2. Verify the response includes:
   - `jwks_uri` pointing to your JWKS endpoint
   - `id_token_signing_alg_values_supported` including "RS256"

### 2. Verify JWKS Endpoint

Next, check if the JWKS endpoint returns valid keys:

1. Run the "2. JWKS Endpoint" request
2. Verify the response has a `keys` array with at least one key
3. Check that the key includes:
   - `kty`: "RSA"
   - `alg`: "RS256"
   - `use`: "sig"
   - `kid`: A unique key ID
   - `n` and `e` values (modulus and exponent)

### 3. Authorization Code Flow with RS256 Tokens

Now test the full authorization flow to get RS256-signed tokens:

1. Log in to your Frappe instance in a browser
2. Run the "3. Authorization Request" request (this will open a browser window)
3. You will be redirected to the redirect URI with a code parameter
4. Copy the code from the URL (e.g., `http://localhost?code=ABC123`)
5. Set the `code` variable in the Postman collection with the value you copied
6. Run the "4. Exchange Code for Token" request
7. Verify you receive:
   - `access_token`
   - `id_token`
   - `refresh_token`

### 4. Verify RS256 Signature

To verify the token is signed with RS256:

1. Run the "5. Inspect ID Token" request
2. Look at the test results and console output
3. Verify the token header has:
   - `alg`: "RS256"
   - `kid`: matching a key in your JWKS response

### 5. Try Other API Calls

You can now test using the token:

1. Run the "6. Userinfo Endpoint" request to get user information
2. Run the "7. Refresh Token" request to get a new access token
3. Run the "8. Token Introspection" request to verify token validity
4. Run the "9. Revoke Token" request to invalidate the token

## Troubleshooting

### Common Issues

1. **"Token has invalid signature" error**:
   - Ensure JWKS is enabled in OAuth Provider Settings
   - Check that the public key in JWKS endpoint matches the private key used for signing

2. **"No matching key found in JWKS" error**:
   - Verify the `kid` in the token header matches a key in the JWKS response
   - Try forcing key rotation and generating new keys

3. **"Algorithm not supported" error**:
   - Make sure the client supports RS256 algorithm

### Debugging

To debug issues, you can:

1. Enable verbose logging in your Frappe instance:
   ```bash
   bench --site your-site set-config --global log_level "debug"
   ```

2. Check the logs for errors:
   ```bash
   tail -f /path/to/frappe-bench/logs/frappe.log
   ```

3. Use JWT debugging tools:
   - [JWT.io](https://jwt.io/) to inspect your tokens
   - You can paste your token and your public key to verify the signature

### Resetting the JWKS Keys

If you need to generate new keys:

1. Go to "Integrations" > "OAuth Provider Settings"
2. Clear the "JWKS Private Key" and "JWKS Public Key" fields
3. Save the settings (new keys will be automatically generated)

## Additional Resources

- [OpenID Connect Core Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [JWT and JWK Specification](https://datatracker.ietf.org/doc/html/rfc7517)
- [OAuth 2.0 for Browser-Based Apps](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps) 