from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from app.simulator import EVENT_PROFILES, IncidentSimulator


simulator = IncidentSimulator()


def create_app() -> Flask:
    app = Flask(__name__, template_folder="../templates", static_folder="../static")

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            events=simulator.events,
            summary=simulator.summary(),
            event_types=list(EVENT_PROFILES.keys()),
        )

    @app.post("/simulate")
    def simulate():
        payload = request.get_json(silent=True) or request.form
        event_type = payload.get("event_type", "port_scan")
        source_ip = payload.get("source_ip") or None

        event = simulator.generate_event(event_type=event_type, source_ip=source_ip)

        if request.is_json:
            return jsonify({"event": event.__dict__, "summary": simulator.summary()})
        return index()

    @app.post("/reset")
    def reset():
        simulator.events.clear()
        if request.is_json:
            return jsonify({"status": "ok", "summary": simulator.summary()})
        return index()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
