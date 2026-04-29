import urllib.request, json

# Issue a token
issue_data = json.dumps({"agent_id": "doc_agent", "delegated_user": "user_1"}).encode()
req = urllib.request.Request('http://127.0.0.1:8000/api/delegate/issue-root', data=issue_data, headers={'Content-Type': 'application/json'})
resp = urllib.request.urlopen(req)
token = json.loads(resp.read().decode())['token']
print("Token issued OK")

# Test introspect with POST + query param
try:
    req2 = urllib.request.Request('http://127.0.0.1:8000/api/delegate/introspect?token=' + urllib.request.quote(token), method='POST', headers={'Content-Type': 'application/json'})
    resp2 = urllib.request.urlopen(req2)
    result = json.loads(resp2.read().decode())
    print("Introspect OK:", "active=" + str(result.get("active")), "revoked=" + str(result.get("revoked")))
except Exception as e:
    print("Introspect FAILED:", e)
