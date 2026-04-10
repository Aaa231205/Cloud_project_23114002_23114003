#!/bin/bash

API_URL="https://localhost:8443/api"
USERNAME="attacker_$(date +%s)"
PASSWORD="password123"

echo "Waiting for services to be ready..."
sleep 2

echo "------------------------------------------------"
echo "1. Registering attacker account"
curl -k -s -X POST "${API_URL}/auth/register?username=${USERNAME}&password=${PASSWORD}" > /dev/null

echo "2. Logging in to get a valid token"
LOGIN_RESPONSE=$(curl -k -s -X POST "${API_URL}/auth/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${USERNAME}&password=${PASSWORD}")

VALID_TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"access_token": *"[^"]*"' | cut -d'"' -f4)

if [ -z "$VALID_TOKEN" ]; then
    echo "Error: Failed to get valid access token"
    exit 1
fi

echo "Valid Token received: ${VALID_TOKEN:0:20}..."

echo "------------------------------------------------"
echo "3. Testing with valid token (Baseline)"
PROFILE_RESPONSE=$(curl -k -s -X GET "${API_URL}/users/me" \
    -H "Authorization: Bearer $VALID_TOKEN")

if [[ $PROFILE_RESPONSE == *"attacker_"* ]]; then
    echo "SUCCESS: Valid token works."
else
    echo "FAILURE: Valid token did not work."
    exit 1
fi

echo "------------------------------------------------"
echo "4. Testing with modified signature"
# Split the valid token and modify the signature part
HEADER_PAYLOAD=$(echo "$VALID_TOKEN" | cut -d'.' -f1,2)
MODIFIED_TOKEN="${HEADER_PAYLOAD}.invalid_signature_part"

MODIFIED_RESPONSE=$(curl -k -s -X GET "${API_URL}/users/me" \
    -H "Authorization: Bearer $MODIFIED_TOKEN")

echo "Response: $MODIFIED_RESPONSE"
if [[ "$MODIFIED_RESPONSE" == *"Not authenticated"* ]] || [[ "$MODIFIED_RESPONSE" == *"Could not validate"* ]]; then
    echo "SUCCESS: Modified signature blocked."
else
    echo "FAILURE: Modified signature accepted!"
fi

echo "------------------------------------------------"
echo "5. Testing with 'none' algorithm"
# Header for 'none' alg: {"alg":"none","typ":"JWT"} -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
# Keep the payload from the valid token
PAYLOAD=$(echo "$VALID_TOKEN" | cut -d'.' -f2)
NONE_ALG_TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.${PAYLOAD}."

NONE_RESPONSE=$(curl -k -s -X GET "${API_URL}/users/me" \
    -H "Authorization: Bearer $NONE_ALG_TOKEN")

echo "Response: $NONE_RESPONSE"
if [[ "$NONE_RESPONSE" == *"Not authenticated"* ]] || [[ "$NONE_RESPONSE" == *"Could not validate"* ]]; then
    echo "SUCCESS: 'none' algorithm blocked."
else
    echo "FAILURE: 'none' algorithm accepted!"
fi

echo "------------------------------------------------"
echo "6. Testing with completely malformed token"
MALFORMED_TOKEN="this.is.not.a.valid.jwt"

MALFORMED_RESPONSE=$(curl -k -s -X GET "${API_URL}/users/me" \
    -H "Authorization: Bearer $MALFORMED_TOKEN")

echo "Response: $MALFORMED_RESPONSE"
if [[ "$MALFORMED_RESPONSE" == *"Not authenticated"* ]] || [[ "$MALFORMED_RESPONSE" == *"Could not validate"* ]]; then
    echo "SUCCESS: Malformed token blocked."
else
    echo "FAILURE: Malformed token accepted!"
fi
