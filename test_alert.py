import requests, sys
sys.stdout.reconfigure(encoding='utf-8')

print("=== Test: reset-all API ===")
r = requests.post('http://127.0.0.1:8000/api/governance/reset-all')
print(f"  Status: {r.status_code}")
print(f"  Response: {r.json()}")

print("\n=== Test: feishu platform demo (simulating frontend) ===")
r = requests.post('http://127.0.0.1:8000/api/governance/reset-all')
print(f"  Reset: {r.status_code}")
r = requests.post('http://127.0.0.1:8000/api/feishu/test', json={"user_id": "feishu_demo_user", "message": "帮我生成财务报告", "platform": "feishu"})
print(f"  Feishu test: {r.status_code}")
d = r.json()
print(f"  status={d.get('status')} trust={d.get('trust_score')} platform={d.get('platform')}")

print("\n=== Test: web platform demo ===")
r = requests.post('http://127.0.0.1:8000/api/governance/reset-all')
r = requests.post('http://127.0.0.1:8000/api/feishu/test', json={"user_id": "web_demo_user", "message": "帮我查一下财务数据", "platform": "web"})
d = r.json()
print(f"  Web test: status={d.get('status')} trust={d.get('trust_score')}")

print("\n=== Test: api platform demo ===")
r = requests.post('http://127.0.0.1:8000/api/governance/reset-all')
r = requests.post('http://127.0.0.1:8000/api/feishu/test', json={"user_id": "api_demo_user", "message": "读取薪资数据", "platform": "api"})
d = r.json()
print(f"  API test: status={d.get('status')} trust={d.get('trust_score')}")

print("\n=== Test: cross-platform demo ===")
r = requests.post('http://127.0.0.1:8000/api/governance/demo/cross-platform')
d = r.json()
print(f"  Demo: {r.status_code}")
for s in d.get('steps', []):
    print(f"    Step {s['step']}: {s['platform']} -> {s['status']}")
