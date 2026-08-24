# StudioFace AI

A polished Flask workspace for photography/video studios with client accounts, email OTP signup, Google Drive event delivery, upload validation and an admin activity console.

## Production setup

1. Create a Render PostgreSQL database and put its connection string in `DATABASE_URL`.
2. Create a Google OAuth Web application. Add exactly:
   `https://studioface.onrender.com/oauth2callback`
   to Authorized redirect URIs.
3. Add the variables from `.env.example` to the Render service environment.
4. Deploy with `render.yaml` or use `gunicorn --workers 2 --threads 4 --timeout 180 --bind 0.0.0.0:$PORT app:app`.
5. Open `/healthz` and confirm the JSON status is `ok`.

## Security rules

Never commit `.env`, real OAuth secrets, Brevo keys, or production database credentials.
Rotate any OAuth client secret that has previously been exposed in source, chat logs, screenshots or commits.

## Important architecture note

Render's local filesystem should not be treated as permanent storage. Production data should live in Postgres, while original media should live in Google Drive or object storage.

## UI

The included `templates/` and `static/` provide a modern responsive StudioFace interface. Replace the logo/brand copy or extend the dashboard as the product grows.
