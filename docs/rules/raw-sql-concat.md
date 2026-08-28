# injection/raw-sql-concat

## Description
Detects interpolated or concatenated SQL that reaches a recognized query sink.

## Why is this a problem?
Building SQL queries by directly inserting variables into the query string leads to SQL Injection (SQLi). An attacker can manipulate the input to alter the structure of the SQL query, allowing them to bypass authentication, access, modify, or delete unauthorized data, or even execute administrative operations on the database.

## How to fix
1. Never use string concatenation (`+`) or template literals (`` `SELECT * FROM users WHERE id = ${id}` ``) for SQL queries.
2. Always use parameterized queries or prepared statements provided by your database driver (e.g., `db.query('SELECT * FROM users WHERE id = $1', [id])`).
3. Alternatively, use a safe ORM (Object-Relational Mapper) or query builder like Prisma, Drizzle, or Kysely, which handle parameterization automatically.

## Context and False Positives

The rule is syntax-first and uses the shared bounded-flow traversal. It recognizes
the following source labels when the AST makes them visible:

- `request.json()` and `request.formData()`;
- `req.body` and `req.query`;
- `searchParams.get(...)`;
- route-parameter members such as `params.id`.

Recognized query sinks include `query` and `execute` member calls on common
database clients, plus `$queryRaw` and `$executeRaw` call/tag forms. Direct
interpolation at a recognized sink remains a review signal even when a source
path cannot be proven. The bounded path adds an `evidencePath` only when the
source-to-sink relationship is visible.

The flow follows direct expressions, SQL-valued local variables, and at most two
same-function identifier aliases. A SQL-looking template assigned to a variable
is not reported until it reaches a recognized sink. Reassignment, mutation,
unknown call escape, function boundaries, cross-file flow, dynamic properties,
and aliases beyond the two-hop limit stop evidence propagation. These are
intentional under-approximations, not proofs that the value is safe.

The highest-risk pattern is user-controlled input reaching a real query sink such as `db.query`, `connection.execute`, or an unsafe raw SQL API. Parameterized queries with placeholders and a separate values array are not treated as the same interpolation pattern. Treat findings as review signals and confirm whether the SQL string is actually executed.

Custom query wrappers, type-aware sink resolution, cross-function flow, and
full SQL parser/semantic analysis remain limitations. The current bounded slice
does not execute scanned repository code and does not use TypeChecker or a
project-wide call graph.
