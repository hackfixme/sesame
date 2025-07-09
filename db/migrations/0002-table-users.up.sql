CREATE TABLE users (
  id                INTEGER      NOT NULL PRIMARY KEY,
  created_at        TIMESTAMP    NOT NULL,
  updated_at        TIMESTAMP    NOT NULL,
  name              VARCHAR(32)  UNIQUE NOT NULL
);
