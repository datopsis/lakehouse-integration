-- Explicit one-time provisioning of a fresh development database, as postgres.
-- The password is read inside the container; never put it in SQL or argv.
\set ON_ERROR_STOP on
\set lakekeeper_password `cat /run/secrets/lakekeeper-password`
BEGIN;
CREATE ROLE lakekeeper LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS PASSWORD :'lakekeeper_password';
ALTER DATABASE lakekeeper OWNER TO lakekeeper;
COMMIT;
\unset lakekeeper_password
-- Use the database image's packaged, opt-in initialization path.
\i /usr/share/lakekeeper/init.sql
