#!/bin/bash

API_URL="https://localhost:8443/api"
USER_A="user_$(date +%s)"
ADMIN_A="admin_$(date +%s)"
PASSWORD="password123"
ADMIN_SECRET="supersecretadmin"

echo "Waiting for services to be ready..."
sleep 2

echo "------------------------------------------------"
echo "1. Registering standard user"
curl -k -s -X POST "${API_URL}/auth/register?username=${USER_A}&password=${PASSWORD}&role=user" > /dev/null

echo "2. Logging in as standard user"
LOGIN_RESPONSE=$(curl -k -s -X POST "${API_URL}/auth/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${USER_A}&password=${PASSWORD}")
USER_TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"access_token": *"[^"]*"' | cut -d'"' -f4)

echo "3. User accessing '/users/me'"
PROFILE_RESPONSE=$(curl -k -s -X GET "${API_URL}/users/me" -H "Authorization: Bearer $USER_TOKEN")
echo "Response: $PROFILE_RESPONSE"

echo "4. User attempting to access '/admin/dashboard'"
ADMIN_RESPONSE=$(curl -k -s -X GET "${API_URL}/admin/dashboard" -H "Authorization: Bearer $USER_TOKEN")
echo "Response: $ADMIN_RESPONSE"
if [[ "$ADMIN_RESPONSE" == *"Not enough permissions"* ]]; then
    echo "SUCCESS: Standard user is blocked from admin dashboard (403 Forbidden)."
else
    echo "FAILURE: Standard user gained access to admin dashboard!"
    exit 1
fi

echo "------------------------------------------------"
echo "5. Registering admin user securely"
curl -k -s -X POST "${API_URL}/auth/register?username=${ADMIN_A}&password=${PASSWORD}&role=admin&admin_secret=${ADMIN_SECRET}" > /dev/null

echo "6. Logging in as admin user"
ADMIN_LOGIN_RESPONSE=$(curl -k -s -X POST "${API_URL}/auth/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${ADMIN_A}&password=${PASSWORD}")
ADMIN_TOKEN=$(echo $ADMIN_LOGIN_RESPONSE | grep -o '"access_token": *"[^"]*"' | cut -d'"' -f4)

echo "7. Admin attempting to access '/admin/dashboard'"
ADMIN_DASH_RESPONSE=$(curl -k -s -X GET "${API_URL}/admin/dashboard" -H "Authorization: Bearer $ADMIN_TOKEN")
echo "Response: $ADMIN_DASH_RESPONSE"
if [[ "$ADMIN_DASH_RESPONSE" == *"Welcome to the admin dashboard"* ]]; then
    echo "SUCCESS: Admin successfully accessed admin dashboard."
else
    echo "FAILURE: Admin could not access admin dashboard!"
    exit 1
fi

echo "------------------------------------------------"
echo "8. Testing invalid secret for admin registration"
INVALID_REG=$(curl -k -s -X POST "${API_URL}/auth/register?username=fakeadmin&password=${PASSWORD}&role=admin&admin_secret=wrong")
echo "Response: $INVALID_REG"
if [[ "$INVALID_REG" == *"Invalid admin secret"* ]]; then
    echo "SUCCESS: Blocked invalid admin creation."
else
    echo "FAILURE: Created admin without valid secret!"
    exit 1
fi

echo "RBAC test script completed successfully."
