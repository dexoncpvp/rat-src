# Optimizer Panel Unified

This is the new, structured, and scalable backend for the Optimizer Panel.

## Structure

- **app/**: Main application code.
  - **api/**: API endpoints (v1).
  - **core/**: Configuration, database, security.
  - **models/**: Database models.
  - **services/**: Business logic (Builder, Stream Manager).
  - **schemas/**: Pydantic schemas for validation.
- **static/**: Static assets.
- **templates/**: HTML templates.

## Features

- **Unified Backend**: Handles both Free and Premium users.
- **Plan-based Access**: Data is filtered based on the user's plan (`free` or `premium`).
- **Web Builder**: Build the mod directly via the API (replacing the Discord bot).
- **Optimized Streaming**: Dedicated StreamManager and SocketIO handlers.
- **Scalable**: Built with FastAPI and SQLAlchemy (ready for PostgreSQL).

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the server:
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

## API Documentation

Once running, visit `http://localhost:8000/docs` for the interactive API documentation.

## Migration Notes

- The frontend `index.html` has been copied to `templates/`. You will need to update the JavaScript API calls to point to `/api/v1/...`.
- The database will be initialized automatically on first run (`optimizer_unified.db`).
