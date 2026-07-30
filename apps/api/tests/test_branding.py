from fastapi.testclient import TestClient

from app.main import app, settings


client = TestClient(app)


def test_public_api_branding_is_phishphage_ai():
    assert settings.app_name == 'PhishPhage AI API'
    assert app.title == 'PhishPhage AI API'
    assert app.openapi()['info']['title'] == 'PhishPhage AI API'
    assert client.get('/').json()['message'] == 'PhishPhage AI API is running'
    assert client.get('/api/v1/health').json()['service'] == 'PhishPhage AI API'
