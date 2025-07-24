-- Drop tables if they exist to start fresh
DROP TABLE IF EXISTS "transaction";
DROP TABLE IF EXISTS book_request;
DROP TABLE IF EXISTS book;
DROP TABLE IF EXISTS user;

-- User Table
CREATE TABLE user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member' -- 'admin' or 'member'
);

-- Book Table
CREATE TABLE book (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  author TEXT NOT NULL,
  isbn TEXT UNIQUE NOT NULL,
  quantity INTEGER NOT NULL DEFAULT 1,
  quantity_available INTEGER NOT NULL DEFAULT 1
);

-- Transaction Table (for issued/returned books)
CREATE TABLE "transaction" (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  book_id INTEGER NOT NULL,
  member_id INTEGER NOT NULL,
  issue_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  due_date TIMESTAMP NOT NULL,
  return_date TIMESTAMP,
  status TEXT NOT NULL DEFAULT 'issued', -- 'issued' or 'returned'
  fine REAL NOT NULL DEFAULT 0.0,
  FOREIGN KEY (book_id) REFERENCES book (id),
  FOREIGN KEY (member_id) REFERENCES user (id)
);

-- Book Request Table (for online requests from members)
CREATE TABLE book_request (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  book_id INTEGER NOT NULL,
  member_id INTEGER NOT NULL,
  request_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'approved', 'denied'
  FOREIGN KEY (book_id) REFERENCES book (id),
  FOREIGN KEY (member_id) REFERENCES user (id)
);