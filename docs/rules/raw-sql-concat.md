# injection/raw-sql-concat

## Description
Detects interpolated SQL passed directly to a recognized query sink.

## Why is this a problem?
Building SQL queries by directly inserting variables into the query string leads to SQL Injection (SQLi). An attacker can manipulate the input to alter the structure of the SQL query, allowing them to bypass authentication, access, modify, or delete unauthorized data, or even execute administrative operations on the database.

## How to fix
1. Never use string concatenation (`+`) or template literals (`` `SELECT * FROM users WHERE id = ${id}` ``) for SQL queries.
2. Always use parameterized queries or prepared statements provided by your database driver (e.g., `db.query('SELECT * FROM users WHERE id = $1', [id])`).
3. Alternatively, use a safe ORM (Object-Relational Mapper) or query builder like Prisma, Drizzle, or Kysely, which handle parameterization automatically.

## Context and False Positives

The current rule uses syntax-level AST matching for direct call arguments and tagged-template query sinks such as `db.query(...)`, `connection.execute(...)`, and ``prisma.$queryRaw`...` ``. Plain SQL-like template strings assigned to a variable are intentionally outside the current flow boundary unless they are passed directly to a recognized sink.

The highest-risk pattern is user-controlled input reaching a real query sink such as `db.query`, `connection.execute`, or an unsafe raw SQL API. Parameterized queries with placeholders and a separate values array are not treated as the same interpolation pattern. Treat findings as review signals and confirm whether the SQL string is actually executed.

Variable flow across separate statements, custom query wrappers, and type-aware sink resolution remain limitations. A future version may extend the sink model after benchmark coverage shows that the added reach improves signal without recreating broad string noise.
