-- user provisioning
CREATE USER app IDENTIFIED BY 'hunter2';
GRANT ALL PRIVILEGES ON app.* TO 'app'@'%';
GRANT SELECT ON app.logs TO PUBLIC;

CREATE PROCEDURE search_users(IN term VARCHAR(100))
BEGIN
  SET @sql = 'SELECT * FROM users WHERE name = ''' + term + '''';
  EXEC(@sql);
END;

DELETE FROM sessions;
UPDATE accounts SET status = 'active';

SELECT * FROM users WITH (NOLOCK);
EXEC xp_cmdshell 'whoami';
SELECT LOAD_FILE('/etc/passwd');
SELECT name INTO OUTFILE '/tmp/out.txt' FROM users;
