CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);

CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    sender_id TEXT NOT NULL,
    receiver_id TEXT NOT NULL,
    message TEXT,
    message_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	was_seen BOOL DEFAULT FALSE NOT NULL
);


-- INSERT INTO users (username, password)
-- VALUES ('admin', 'some_hash'); 

