import os
import sys

# Tests import backend modules (api, feature_extraction) by their flat names,
# the same way uvicorn does when run from the backend directory.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
