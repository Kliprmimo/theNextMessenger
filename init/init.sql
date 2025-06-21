CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);

CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    sender_id TEXT NOT NULL,
    reciever_id TEXT NOT NULL,
    message TEXT,
    message_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- INSERT INTO users (username, password)
-- VALUES ('admin', 'some_hash'); 

