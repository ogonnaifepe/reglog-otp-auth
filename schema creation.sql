-- Connect as SYSTEM or SYS
-- Create user/schema
CREATE USER getby IDENTIFIED BY YourStrongPassword123;

-- Grant necessary privileges
GRANT CONNECT, RESOURCE, CREATE SESSION, CREATE TABLE, CREATE SEQUENCE, CREATE TRIGGER TO getby;

-- Grant unlimited tablespace
GRANT UNLIMITED TABLESPACE TO getby;

-- Additional grants for the application
GRANT CREATE PROCEDURE, CREATE VIEW TO getby;

-- Check if user created
SELECT username, account_status FROM dba_users WHERE username = 'GETBY';


ALTER USER getby DEFAULT TABLESPACE RUBIKONDAT01;




user creted via registration API:

{
  "email": "ogonnaifepe@gmail.com",
  "password": "stringst",
  "confirm_password": "stringst"
}