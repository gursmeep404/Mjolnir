import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "database", "results.db")

DEBUG = True  # Set to False in production
SECRET_KEY = "your-secret-key"
