CREATE TABLE users (
   id UUID PRIMARY KEY,
   name VARCHAR (50) NOT NULL,
   email VARCHAR (300) UNIQUE NOT NULL,
   hashword BYTEA NOT NULL,
   active BOOLEAN NOT NULL,
   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
   updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sessions (
   id UUID PRIMARY KEY,
   user_id UUID NOT NULL REFERENCES users(id),
   access_token VARCHAR(32) NOT NULL,
   refresh_token VARCHAR(32) NOT NULL,
   ended_at TIMESTAMP,
   expires_at TIMESTAMPTZ NOT NULL,
   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
   updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE api_credentials (
   id UUID PRIMARY KEY,
   active BOOLEAN NOT NULL,
   client_id VARCHAR(32) NOT NULL,
   client_secret BYTEA NOT NULL,
   created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
   updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)