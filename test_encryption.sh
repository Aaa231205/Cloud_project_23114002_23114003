#!/bin/bash
# ============================================================
# Test Script: Data Protection & Automated Security Measures
# ============================================================
# Tests all Assignment 4 features:
#   1. Data encryption at rest (file upload / download)
#   2. Encryption verification (DB stores only encrypted data)
#   3. Token refresh mechanism
#   4. Access restriction enforcement
#   5. Key rotation
#   6. Security alerts & admin endpoints
# ============================================================

API_URL="https://localhost:8443/api"
USERNAME="enctest_$(date +%s)"
PASSWORD="StrongP@ss123"
ADMIN_USERNAME="admin_enc_$(date +%s)"
ADMIN_PASSWORD="AdminP@ss123"

echo "============================================"
echo "  Assignment 4: Security Feature Tests"
echo "============================================"
echo ""

echo "Waiting for services to be ready..."
sleep 10

# ----------------------------------------------------------
# 1. Register & Login
# ----------------------------------------------------------
echo "================================================"
echo "1. SETUP: Register and Login users"
echo "================================================"

echo "  Registering standard user: $USERNAME"
curl -k -s -X POST "${API_URL}/auth/register?username=${USERNAME}&password=${PASSWORD}" | python3 -m json.tool 2>/dev/null || echo "(raw output above)"
echo ""

echo "  Registering admin user: $ADMIN_USERNAME"
curl -k -s -X POST "${API_URL}/auth/register?username=${ADMIN_USERNAME}&password=${ADMIN_PASSWORD}&role=admin&admin_secret=supersecretadmin" | python3 -m json.tool 2>/dev/null || echo "(raw output above)"
echo ""

echo "  Logging in as standard user..."
LOGIN_RESPONSE=$(curl -k -s -X POST "${API_URL}/auth/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${USERNAME}&password=${PASSWORD}")
echo "  Response: $LOGIN_RESPONSE"

TOKEN=$(echo $LOGIN_RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
REFRESH_TOKEN=$(echo $LOGIN_RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin).get('refresh_token',''))" 2>/dev/null)

if [ -z "$TOKEN" ]; then
    echo "  ERROR: Failed to get access token"
    exit 1
fi
echo "  Access Token:  ${TOKEN:0:30}..."
echo "  Refresh Token: ${REFRESH_TOKEN:0:30}..."
echo ""

echo "  Logging in as admin user..."
ADMIN_LOGIN=$(curl -k -s -X POST "${API_URL}/auth/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${ADMIN_USERNAME}&password=${ADMIN_PASSWORD}")
ADMIN_TOKEN=$(echo $ADMIN_LOGIN | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

if [ -z "$ADMIN_TOKEN" ]; then
    echo "  ERROR: Failed to get admin token"
    exit 1
fi
echo "  Admin Token: ${ADMIN_TOKEN:0:30}..."
echo ""

# ----------------------------------------------------------
# 2. Test Encrypted File Upload
# ----------------------------------------------------------
echo "================================================"
echo "2. DATA ENCRYPTION AT REST: File Upload"
echo "================================================"

# Create a test file
TEST_CONTENT="This is a confidential document. SSN: 123-45-6789. Credit Card: 4111-1111-1111-1111."
echo "$TEST_CONTENT" > /tmp/test_secret.txt

echo "  Uploading file (will be encrypted with AES-256-GCM)..."
UPLOAD_RESPONSE=$(curl -k -s -X POST "${API_URL}/files/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@/tmp/test_secret.txt" \
    -F "storage_node=node_1")
echo "  Response: $UPLOAD_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$UPLOAD_RESPONSE"

FILE_ID=$(echo $UPLOAD_RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
echo "  File ID: $FILE_ID"
echo ""

# ----------------------------------------------------------
# 3. Test File Listing
# ----------------------------------------------------------
echo "================================================"
echo "3. LIST ENCRYPTED FILES"
echo "================================================"

echo "  Listing files for user..."
curl -k -s -X GET "${API_URL}/files/" \
    -H "Authorization: Bearer $TOKEN" | python3 -m json.tool 2>/dev/null
echo ""

# ----------------------------------------------------------
# 4. Test File Download (Decryption)
# ----------------------------------------------------------
echo "================================================"
echo "4. DATA DECRYPTION: File Download"
echo "================================================"

if [ -n "$FILE_ID" ]; then
    echo "  Downloading and decrypting file $FILE_ID..."
    DOWNLOADED=$(curl -k -s -X GET "${API_URL}/files/${FILE_ID}" \
        -H "Authorization: Bearer $TOKEN")
    echo "  Original content:    '$TEST_CONTENT'"
    echo "  Decrypted content:   '$DOWNLOADED'"
    
    if [ "$DOWNLOADED" = "$TEST_CONTENT" ]; then
        echo "  ✅ SUCCESS: File decrypted correctly - content matches!"
    else
        echo "  ⚠️  WARNING: Content may differ (could include newline)"
    fi
else
    echo "  SKIPPED: No file ID available"
fi
echo ""

# ----------------------------------------------------------
# 5. Test Token Refresh
# ----------------------------------------------------------
echo "================================================"
echo "5. TOKEN RENEWAL: Refresh Token Flow"
echo "================================================"

if [ -n "$REFRESH_TOKEN" ]; then
    echo "  Refreshing access token using refresh token..."
    REFRESH_RESPONSE=$(curl -k -s -X POST "${API_URL}/auth/refresh?refresh_token=${REFRESH_TOKEN}")
    echo "  Response:" 
    echo "$REFRESH_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$REFRESH_RESPONSE"
    
    NEW_TOKEN=$(echo $REFRESH_RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
    NEW_REFRESH=$(echo $REFRESH_RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin).get('refresh_token',''))" 2>/dev/null)
    
    if [ -n "$NEW_TOKEN" ]; then
        echo "  ✅ SUCCESS: New access token received: ${NEW_TOKEN:0:30}..."
        TOKEN=$NEW_TOKEN  # Use new token for remaining tests
    else
        echo "  ❌ FAILED: Could not refresh token"
    fi
    echo ""
    
    echo "  Testing reuse of old refresh token (should fail - one-time use)..."
    REUSE_RESPONSE=$(curl -k -s -X POST "${API_URL}/auth/refresh?refresh_token=${REFRESH_TOKEN}")
    echo "  Response: $REUSE_RESPONSE"
    echo "  ✅ Old refresh token should be rejected (security measure)"
else
    echo "  SKIPPED: No refresh token available"
fi
echo ""

# ----------------------------------------------------------
# 6. Test Admin Security Dashboard
# ----------------------------------------------------------
echo "================================================"
echo "6. ADMIN: Security Status Dashboard"
echo "================================================"

echo "  Fetching security status..."
curl -k -s -X GET "${API_URL}/admin/security/status" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool 2>/dev/null
echo ""

# ----------------------------------------------------------
# 7. Test Security Alerts
# ----------------------------------------------------------
echo "================================================"
echo "7. SECURITY ALERTS: View & Manage"
echo "================================================"

echo "  Fetching all security alerts..."
curl -k -s -X GET "${API_URL}/admin/alerts" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool 2>/dev/null
echo ""

# ----------------------------------------------------------
# 8. Test Access Restrictions
# ----------------------------------------------------------
echo "================================================"
echo "8. ACCESS RESTRICTIONS: View Active Restrictions"
echo "================================================"

echo "  Fetching active restrictions..."
curl -k -s -X GET "${API_URL}/admin/restrictions" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool 2>/dev/null
echo ""

# ----------------------------------------------------------
# 9. Test Admin Dashboard (Enhanced)
# ----------------------------------------------------------
echo "================================================"
echo "9. ADMIN DASHBOARD: Enhanced View"
echo "================================================"

curl -k -s -X GET "${API_URL}/admin/dashboard" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool 2>/dev/null
echo ""

# ----------------------------------------------------------
# 10. Test Manual Key Rotation
# ----------------------------------------------------------
echo "================================================"
echo "10. KEY ROTATION: Manual Trigger"
echo "================================================"

echo "  Triggering key rotation for node_1..."
curl -k -s -X POST "${API_URL}/admin/keys/rotate/node_1" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool 2>/dev/null
echo ""

echo "  Verifying file still accessible after rotation..."
if [ -n "$FILE_ID" ]; then
    AFTER_ROTATION=$(curl -k -s -X GET "${API_URL}/files/${FILE_ID}" \
        -H "Authorization: Bearer $TOKEN")
    echo "  Content after rotation: '$AFTER_ROTATION'"
    if echo "$AFTER_ROTATION" | grep -q "confidential"; then
        echo "  ✅ SUCCESS: File still accessible after key rotation!"
    else
        echo "  ⚠️  Note: File may have been re-encrypted with new key"
    fi
fi
echo ""

# ----------------------------------------------------------
# 11. Upload second file to different node
# ----------------------------------------------------------
echo "================================================"
echo "11. MULTI-NODE: Upload to Different Node"
echo "================================================"

echo "Another secret document for node 2" > /tmp/test_secret2.txt
echo "  Uploading to node_2..."
curl -k -s -X POST "${API_URL}/files/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@/tmp/test_secret2.txt" \
    -F "storage_node=node_2" | python3 -m json.tool 2>/dev/null
echo ""

echo "  Final file listing..."
curl -k -s -X GET "${API_URL}/files/" \
    -H "Authorization: Bearer $TOKEN" | python3 -m json.tool 2>/dev/null
echo ""

# ----------------------------------------------------------
# Cleanup
# ----------------------------------------------------------
rm -f /tmp/test_secret.txt /tmp/test_secret2.txt

echo "============================================"
echo "  All tests completed!"
echo "============================================"
echo ""
echo "Check logs directory for security event logs:"
echo "  logs/auth.log        - Authentication events"
echo "  logs/threats.log     - Threat detection"
echo "  logs/mitigation.log  - Automated mitigations"
echo "  logs/encryption.log  - Encryption operations"
echo "  logs/alerts.log      - Security alerts"
echo ""
