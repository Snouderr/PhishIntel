import os
import sys

# Tests import backend modules (api, feature_extraction) by their flat names,
# the same way uvicorn does when run from the backend directory.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def client():
    import api
    with TestClient(api.app) as c:
        yield c
