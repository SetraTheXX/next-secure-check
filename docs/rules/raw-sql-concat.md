# injection/raw-sql-concat

## Description
Detects the use of string concatenation or template literals to build SQL queries.

## Why is this a problem?
Building SQL queries by directly inserting variables into the query string leads to SQL Injection (SQLi). An attacker can manipulate the input to alter the structure of the SQL query, allowing them to bypass authentication, access, modify, or delete unauthorized data, or even execute administrative operations on the database.

## How to fix
1. Never use string concatenation (`+`) or template literals (`` `SELECT * FROM users WHERE id = ${id}` ``) for SQL queries.
2. Always use parameterized queries or prepared statements provided by your database driver (e.g., `db.query('SELECT * FROM users WHERE id = $1', [id])`).
3. Alternatively, use a safe ORM (Object-Relational Mapper) or query builder like Prisma, Drizzle, or Kysely, which handle parameterization automatically.