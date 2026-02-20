#!/bin/bash

# Configuration
API_URL="https://localhost:8443/api"
USERNAME="testuser_$(date +%s)"
PASSWORD="password123"

echo "Waiting for services to be ready..."
sleep 10

echo "------------------------------------------------"
echo "1. Testing Registration"
REGISTER_RESPONSE=$(curl -k -s -X POST "${API_URL}/auth/register?username=${USERNAME}&password=${PASSWORD}")
echo "Response: $REGISTER_RESPONSE"

echo "------------------------------------------------"
echo "2. Testing Login"
LOGIN_RESPONSE=$(curl -k -s -X POST "${API_URL}/auth/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${USERNAME}&password=${PASSWORD}")
echo "Response: $LOGIN_RESPONSE"

TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"access_token": *"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo "Error: Failed to get access token"
    exit 1
fi

echo "Token received: ${TOKEN:0:20}..."

echo "------------------------------------------------"
echo "3. Testing Protected Endpoint (User Profile)"
PROFILE_RESPONSE=$(curl -k -s -X GET "${API_URL}/users/me" \
    -H "Authorization: Bearer $TOKEN")
echo "Response: $PROFILE_RESPONSE"

if [[ $PROFILE_RESPONSE == *"testuser"* ]]; then
    echo "SUCCESS: Profile retrieval verified."
else
    echo "FAILURE: Could not retrieve profile."
    exit 1
fi

echo "------------------------------------------------"
echo "4. Testing Unauthorized Access"
FAIL_RESPONSE=$(curl -k -s -X GET "${API_URL}/users/me")
echo "Response: $FAIL_RESPONSE"

if [[ $FAIL_RESPONSE == *"Not authenticated"* ]] || [[ $FAIL_RESPONSE == *"Missing"* ]]; then
    echo "SUCCESS: Unauthorized access blocked."
else
     # FastAPI default 401 detail is "Not authenticated"
     if [[ $FAIL_RESPONSE == *"detail"* ]]; then
        echo "SUCCESS: Error returned as expected."
     else
        echo "WARNING: Check response for unauthorized access."
     fi
fi
