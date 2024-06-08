from app import run_app
from database import initialize_db

def main():
    initialize_db()
    run_app()

if __name__ == "__main__":
    main()
