-- parameterized, scoped, least-privilege
CREATE PROCEDURE get_user(IN uid INT)
BEGIN
  SELECT id, name, email FROM users WHERE id = uid;
END;

GRANT SELECT, INSERT ON app.orders TO 'app_role';
DELETE FROM sessions WHERE expires_at < NOW();
UPDATE accounts SET status = 'active' WHERE id = 42;
