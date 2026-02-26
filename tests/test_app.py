from app.main import create_app, simulator


def setup_function():
    simulator.events.clear()


def test_index_loads():
    app = create_app()
    client = app.test_client()

    response = client.get("/")
    assert response.status_code == 200
    assert b"Incident Response Simulation Tool" in response.data


def test_simulate_json_event():
    app = create_app()
    client = app.test_client()

    response = client.post("/simulate", json={"event_type": "port_scan", "source_ip": "198.51.100.9"})
    payload = response.get_json()

    assert response.status_code == 200
    assert payload["event"]["event_type"] == "port_scan"
    assert payload["event"]["source_ip"] == "198.51.100.9"
    assert "packet_preview" in payload["event"]
    assert payload["summary"]["total_events"] == 1


def test_reset_json():
    app = create_app()
    client = app.test_client()

    client.post("/simulate", json={"event_type": "dos_attempt"})
    response = client.post("/reset", json={})

    assert response.status_code == 200
    assert response.get_json()["summary"]["total_events"] == 0
