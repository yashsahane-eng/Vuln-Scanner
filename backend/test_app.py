import sys
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

print("--- Test 1: Root serves index.html ---")
res = client.get("/")
assert res.status_code == 200, f"Root returned {res.status_code}"
assert "VulnScan" in res.text or "<div id=\"root\">" in res.text, "Index HTML contents mismatch"
print("PASS: Root page served successfully.")

print("\n--- Test 2: Reject mismatched confirmation ---")
res = client.post("/api/scan", json={"target": "http://localhost:8000", "confirmation": "http://localhost:8080"})
assert res.status_code == 400, f"Expected 400, got {res.status_code}"
print("PASS: Mismatched confirmation rejected.")

print("\n--- Test 3: Reject unsafe domain (google.com) ---")
res = client.post("/api/scan", json={"target": "https://google.com", "confirmation": "https://google.com"})
assert res.status_code == 403, f"Expected 403, got {res.status_code}"
print("PASS: Public/unsafe domain rejected with 403.")

print("\n--- Test 4: Accept valid localhost target ---")
res = client.post("/api/scan", json={"target": "http://127.0.0.1:8000", "confirmation": "http://127.0.0.1:8000"})
assert res.status_code == 200, f"Expected 200, got {res.status_code}"
data = res.json()
assert "scan_id" in data
scan_id = data["scan_id"]
print(f"PASS: Valid scan initiated, scan_id = {scan_id}")

print("\n--- Test 5: WebSocket scan stream ---")
with client.websocket_connect(f"/ws/{scan_id}?target=http://127.0.0.1:8000") as ws:
    received_types = []
    while True:
        msg = ws.receive_json()
        m_type = msg.get("type")
        received_types.append(m_type)
        if m_type == "complete":
            print(f"Scan completed: {msg.get('message')}")
            break
        elif m_type == "error":
            print(f"Received error: {msg}")
            break
assert "complete" in received_types, "Did not receive complete event"
print(f"PASS: WebSocket scan streamed successfully (received types: {set(received_types)}).")

print("\n--- Test 6: Report download JSON ---")
res = client.get(f"/api/report/{scan_id}/json")
assert res.status_code == 200
report_json = res.json()
assert "risk_score" in report_json
assert "findings" in report_json
print(f"PASS: JSON report returned with {len(report_json['findings'])} findings and risk score {report_json['risk_score']['score']}.")

print("\n--- Test 7: Report download HTML ---")
res = client.get(f"/api/report/{scan_id}/html")
assert res.status_code == 200
assert "MISSION DEBRIEF" in res.text
print("PASS: HTML mission debrief report returned successfully.")

print("\nALL 7 AUTOMATED INTEGRATION TESTS PASSED!")
