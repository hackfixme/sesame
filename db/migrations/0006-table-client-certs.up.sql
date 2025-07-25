CREATE TABLE client_certs (
  id             INTEGER      PRIMARY KEY,
  created_at     TIMESTAMP    NOT NULL,
  updated_at     TIMESTAMP    NOT NULL,
  expires_at     TIMESTAMP    NOT NULL,
  serial_number  VARCHAR(32)  NOT NULL,
  user_id        INTEGER      NOT NULL,
  site_id        VARCHAR(32)  NOT NULL,
  renewal_token  BLOB         NOT NULL,
  renewal_token_expires_at  TIMESTAMP  NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
