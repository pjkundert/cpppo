CREATE TABLE sessions (
        session_id 	char(128) UNIQUE NOT NULL,
        atime		integer NOT NULL default current_timestamp,
        data		text,
        PRIMARY KEY (session_id)
);

CREATE TABLE users (
       user_id		integer primary key autoincrement,
       creator		integer,
       name		text default NULL,
       pin		integer default NULL,
       login		integer default 1,
       zones		text default NULL
);

/*
 * licenses -- All license provenance currently available to the License Server
 */

CREATE TABLE licenses (
       signature        char(128) UNIQUE not NULL,      -- base64 512-bit Ed25519 Signature
       license		text,                           -- JSON License serialization
       PRIMARY KEY (signature)
);


