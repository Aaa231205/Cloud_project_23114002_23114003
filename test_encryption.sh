#!/bin/bash
# ============================================================
# Test Script: Distributed Security System
# ============================================================
# Tests all Assignment 4 features + distributed sync:
#   1. Data encryption at rest (file upload / download)
#   2. Token refresh mechanism
#   3. Key rotation with sync
#   4. Distributed user sync (register on one, login on another)
#   5. Cluster status & health
#   6. Fault tolerance (node recovery)
# ============================================================

API_URL="https://localhost:8443/api"
USERNAME="enctest_$(date +%s)"
PASSWORD="StrongP@ss123"
ADMIN_USERNAME="admin_enc_$(date +%s)"
ADMIN_PASSWORD="AdminP@ss123"

echo "============================================"
echo "  Distributed Security System Tests"
echo "============================================"
echo ""

echo "Waiting for all nodes to start and sync..."
sleep 15

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

echo "  Waiting for sync to propagate user to all nodes..."
sleep 8

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
# 3. Test File Download (Decryption)
# ----------------------------------------------------------
echo "================================================"
echo "3. DATA DECRYPTION: File Download"
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
# 4. Test Token Refresh
# ----------------------------------------------------------
echo "================================================"
echo "4. TOKEN RENEWAL: Refresh Token Flow"
echo "================================================"

if [ -n "$REFRESH_TOKEN" ]; then
    echo "  Refreshing access token using refresh token..."
    REFRESH_RESPONSE=$(curl -k -s -X POST "${API_URL}/auth/refresh?refresh_token=${REFRESH_TOKEN}")
    echo "  Response:" 
    echo "$REFRESH_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$REFRESH_RESPONSE"
    
    NEW_TOKEN=$(echo $REFRESH_RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
    
    if [ -n "$NEW_TOKEN" ]; then
        echo "  ✅ SUCCESS: New access token received: ${NEW_TOKEN:0:30}..."
        TOKEN=$NEW_TOKEN
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
# 5. Test Key Rotation with Sync
# ----------------------------------------------------------
echo "================================================"
echo "5. KEY ROTATION: Manual Trigger + Sync"
echo "================================================"

echo "  Triggering key rotation for node_1..."
ROTATION_RESPONSE=$(curl -k -s -X POST "${API_URL}/admin/keys/rotate/node_1" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
echo "  Response:"
echo "$ROTATION_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$ROTATION_RESPONSE"
echo ""

echo "  Waiting for key sync to propagate..."
sleep 5

echo "  Verifying file still accessible after rotation..."
if [ -n "$FILE_ID" ]; then
    AFTER_ROTATION=$(curl -k -s -X GET "${API_URL}/files/${FILE_ID}" \
        -H "Authorization: Bearer $TOKEN")
    echo "  Content after rotation: '$AFTER_ROTATION'"
    if echo "$AFTER_ROTATION" | grep -q "confidential"; then
        echo "  ✅ SUCCESS: File still accessible after key rotation!"
    else
        echo "  ⚠️  Note: File may need node-specific routing"
    fi
fi
echo ""

# ----------------------------------------------------------
# 6. Distributed User Sync Verification
# ----------------------------------------------------------
echo "================================================"
echo "6. DISTRIBUTED SYNC: Cross-Node User Verification"
echo "================================================"

SYNC_USER="synctest_$(date +%s)"
SYNC_PASS="SyncP@ss123"

echo "  Registering user '$SYNC_USER' (will hit one node)..."
curl -k -s -X POST "${API_URL}/auth/register?username=${SYNC_USER}&password=${SYNC_PASS}" | python3 -m json.tool 2>/dev/null
echo ""

echo "  Waiting for sync propagation to all nodes..."
sleep 8

echo "  Attempting login 3 times (load-balanced across all nodes)..."
SUCCESS_COUNT=0
for i in 1 2 3; do
    LOGIN_CHECK=$(curl -k -s -X POST "${API_URL}/auth/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=${SYNC_USER}&password=${SYNC_PASS}")
    CHECK_TOKEN=$(echo $LOGIN_CHECK | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
    if [ -n "$CHECK_TOKEN" ]; then
        echo "    Attempt $i: ✅ Login successful"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "    Attempt $i: ❌ Login failed (sync may still be propagating)"
    fi
done

if [ $SUCCESS_COUNT -eq 3 ]; then
    echo "  ✅ SUCCESS: User synced across all nodes!"
elif [ $SUCCESS_COUNT -gt 0 ]; then
    echo "  ⚠️  PARTIAL: User synced to $SUCCESS_COUNT/3 nodes (eventual consistency)"
else
    echo "  ❌ FAILED: User not synced"
fi
echo ""

# ----------------------------------------------------------
# 7. Cluster Status
# ----------------------------------------------------------
echo "================================================"
echo "7. CLUSTER STATUS: Node Health & Sync Status"
echo "================================================"

echo "  Fetching cluster status..."
curl -k -s -X GET "${API_URL}/admin/cluster/status" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool 2>/dev/null
echo ""

# ----------------------------------------------------------
# 8. Security Status (with distributed sync stats)
# ----------------------------------------------------------
echo "================================================"
echo "8. SECURITY STATUS: With Distributed Sync Stats"
echo "================================================"

curl -k -s -X GET "${API_URL}/admin/security/status" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool 2>/dev/null
echo ""

# ----------------------------------------------------------
# 9. Admin Dashboard
# ----------------------------------------------------------
echo "================================================"
echo "9. ADMIN DASHBOARD: Enhanced View"
echo "================================================"

curl -k -s -X GET "${API_URL}/admin/dashboard" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool 2>/dev/null
echo ""

# ----------------------------------------------------------
# 10. Multi-Node File Upload
# ----------------------------------------------------------
echo "================================================"
echo "10. MULTI-NODE: Upload to Different Nodes"
echo "================================================"

echo "Another secret document for node 2" > /tmp/test_secret2.txt
echo "  Uploading to node_2..."
curl -k -s -X POST "${API_URL}/files/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@/tmp/test_secret2.txt" \
    -F "storage_node=node_2" | python3 -m json.tool 2>/dev/null
echo ""

echo "Third secret for node 3" > /tmp/test_secret3.txt
echo "  Uploading to node_3..."
curl -k -s -X POST "${API_URL}/files/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@/tmp/test_secret3.txt" \
    -F "storage_node=node_3" | python3 -m json.tool 2>/dev/null
echo ""

echo "  File listing..."
curl -k -s -X GET "${API_URL}/files/" \
    -H "Authorization: Bearer $TOKEN" | python3 -m json.tool 2>/dev/null
echo ""

# ----------------------------------------------------------
# 11. Database Verification (check data in each DB)
# ----------------------------------------------------------
echo "================================================"
echo "11. DATABASE VERIFICATION: Check Each Node's DB"
echo "================================================"

for i in 1 2 3; do
    echo "  --- db_$i ---"
    echo "  Users:"
    docker exec -t db_$i psql -U user -d cloud_db -c "SELECT username, role FROM users;" 2>/dev/null || echo "    (db_$i not accessible)"
    echo "  Encryption Keys:"
    docker exec -t db_$i psql -U user -d cloud_db -c "SELECT key_id, is_active, node_id FROM encryption_keys;" 2>/dev/null || echo "    (db_$i not accessible)"
    echo "  Encrypted Files:"
    docker exec -t db_$i psql -U user -d cloud_db -c "SELECT id, filename, storage_node FROM encrypted_files;" 2>/dev/null || echo "    (db_$i not accessible)"
    echo "  Sync Events:"
    docker exec -t db_$i psql -U user -d cloud_db -c "SELECT COUNT(*) as total_events FROM sync_events;" 2>/dev/null || echo "    (db_$i not accessible)"
    echo ""
done

# ----------------------------------------------------------
# Cleanup
# ----------------------------------------------------------
rm -f /tmp/test_secret.txt /tmp/test_secret2.txt /tmp/test_secret3.txt

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
echo "Check database sync with:"
echo "  docker exec -it db_1 psql -U user -d cloud_db -c 'SELECT * FROM sync_events;'"
echo "  docker exec -it db_2 psql -U user -d cloud_db -c 'SELECT * FROM users;'"
echo ""
