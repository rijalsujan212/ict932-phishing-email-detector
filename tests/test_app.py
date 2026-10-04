from src.app import create_app


def test_login_page_loads(tmp_path):
    app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False})
    client = app.test_client()
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Explainable Phishing Email Detector" in response.data


def test_dashboard_requires_authentication():
    app = create_app({"TESTING": True})
    client = app.test_client()
    response = client.get("/dashboard")
    assert response.status_code in (302, 401)
