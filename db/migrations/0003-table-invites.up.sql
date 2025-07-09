CREATE TABLE invites (
  id           INTEGER       PRIMARY KEY,
  uuid         VARCHAR(32)   UNIQUE NOT NULL,
  created_at   TIMESTAMP     NOT NULL,
  updated_at   TIMESTAMP     NOT NULL,
  expires_at   TIMESTAMP     NOT NULL,
  user_id      INTEGER       NOT NULL,
  private_key  BLOB          NOT NULL,
  nonce        BLOB          NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
