import pytest
from app import app, db, Taxi

@pytest.fixture
def client():
    # Configurar el cliente de prueba de Flask
    app.config['TESTING'] = True
    client = app.test_client()

    # Crear la base de datos y agregar algunos datos de prueba
    with app.app_context():
        db.create_all()
        # Insertar datos de prueba
        db.session.add(Taxi(plate="ABC123"))
        db.session.add(Taxi(plate="XYZ789"))
        db.session.commit()

    yield client

    # Limpiar la base de datos después de la prueba
    with app.app_context():
        db.session.remove()
        db.drop_all()

def test_get_taxis(client):
    """Prueba E2E para el endpoint /taxis"""
    
    # Realizar una solicitud GET sin filtros
    response = client.get('/taxis')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data) == 2  # Asegúrate de que obtienes dos taxis

    # Realizar una solicitud GET con el parámetro plate
    response = client.get('/taxis?plate=ABC')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data) == 1  # Debe encontrar solo 1 taxi con "ABC"
    assert data[0]['plate'] == "ABC123"

    # Realizar una solicitud con paginación
    response = client.get('/taxis?page=1&limit=1')
    assert response.status_code == 200
    data = response.get_json()
    assert len(data) == 1  # Solo 1 taxi debido a la paginación

def test_get_taxis_no_results(client):
    """Prueba E2E para el endpoint /taxis sin resultados"""
    
    # Realizar una solicitud GET con un plate que no existe
    response = client.get('/taxis?plate=NONEXISTENT')
    assert response.status_code == 404
    data = response.get_json()
    assert data['message'] == 'No taxis found'
