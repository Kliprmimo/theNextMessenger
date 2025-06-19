CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);


-- INSERT INTO users (username, password)
-- VALUES ('admin', 'some_hash'); 

