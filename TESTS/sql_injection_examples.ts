/**
 * ============================================================
 *  SQL INJECTION VULNERABILITY EXAMPLES — Sentinel Test File
 *  Rule: SENTINEL-SQL-001 | Languages: TypeScript / Python / C#
 * ============================================================
 *
 *  Open this file in VS Code with the Sentinel extension active.
 *  Every marked line below will be underlined with a diagnostic.
 * ============================================================
 */

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  TYPESCRIPT / JAVASCRIPT EXAMPLES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ── 1. Template literal SELECT (most common Node.js pattern) ─────────────────
//  Attacker input: username = "admin' OR '1'='1"
//  Resulting query: SELECT * FROM users WHERE username = 'admin' OR '1'='1'

async function getUserByUsername(username: string, db: any) {
  const query = `SELECT * FROM users WHERE username = '${username}'`;  // ❌ SENTINEL-SQL-001
  return db.execute(query);
}

// ── 2. Template literal INSERT ───────────────────────────────────────────────

async function createProduct(name: string, price: string, db: any) {
  const query = `INSERT INTO products (name, price) VALUES ('${name}', ${price})`;  // ❌ SENTINEL-SQL-001
  return db.execute(query);
}

// ── 3. Template literal UPDATE ───────────────────────────────────────────────

async function updateEmail(userId: string, newEmail: string, db: any) {
  const sql = `UPDATE users SET email = '${newEmail}' WHERE id = ${userId}`;  // ❌ SENTINEL-SQL-001
  return db.execute(sql);
}

// ── 4. Template literal DELETE ───────────────────────────────────────────────
//  Attacker input: id = "1 OR 1=1" → deletes every row

async function deleteRecord(id: string, db: any) {
  const sql = `DELETE FROM orders WHERE id = ${id}`;  // ❌ SENTINEL-SQL-001
  return db.execute(sql);
}

// ── 5. String concatenation SELECT ──────────────────────────────────────────

function buildQuery(searchTerm: string): string {
  return "SELECT * FROM products WHERE name = '" + searchTerm + "'";  // ❌ SENTINEL-SQL-001
}

// ── 6. String concatenation INSERT ──────────────────────────────────────────

function buildInsert(title: string, body: string): string {
  return "INSERT INTO posts (title, body) VALUES ('" + title + "', '" + body + "')";  // ❌ SENTINEL-SQL-001
}

// ── 7. DROP / ALTER statements with variable ─────────────────────────────────
//  If table name is user-supplied: catastrophic

function dropTable(tableName: string, db: any) {
  const sql = "DROP TABLE " + tableName;  // ❌ SENTINEL-SQL-001
  return db.execute(sql);
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  C# / JAVA STRING CONCATENATION EXAMPLES
//  (Sentinel detects these in .cs / .java files)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/*
// C# — string concatenation (VULNERABLE)
string query = "SELECT * FROM users WHERE id = " + userId;               // ❌
SqlCommand cmd = new SqlCommand(query, connection);

// C# — String.Format (VULNERABLE)
string query = String.Format("SELECT * FROM orders WHERE user = '{0}'", username);  // ❌

// Java — PreparedStatement with concatenation (VULNERABLE)
String sql = "SELECT * FROM accounts WHERE email = '" + email + "'";    // ❌
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
*/


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  PYTHON EXAMPLES
//  (Sentinel detects f-strings and % formatting in .py files)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/*
# Python — f-string (VULNERABLE)
query = f"SELECT * FROM users WHERE name = '{username}'"                  # ❌
cursor.execute(query)

# Python — % formatting (VULNERABLE)
query = "SELECT * FROM products WHERE id = %s" % (product_id,)           # ❌
# NOTE: when used with cursor.execute(query, params) it IS safe, but
# building the full string first then passing it is dangerous.

# Python — .format() (VULNERABLE)
query = "DELETE FROM sessions WHERE token = '{}'".format(token)           # ❌
cursor.execute(query)
*/


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  ✅ SAFE EQUIVALENTS (Sentinel will NOT flag these)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ✅ Parameterised query — the ONLY correct approach in TypeScript/Node.js
async function safeGetUser(username: string, db: any) {
  return db.execute("SELECT * FROM users WHERE username = ?", [username]);
}

// ✅ Named parameters (e.g. Knex / Prisma / TypeORM)
async function safeUpdateEmail(userId: number, email: string, prisma: any) {
  return prisma.user.update({
    where: { id: userId },
    data:  { email },
  });
}

/*
# ✅ Python — parameterised query
cursor.execute("SELECT * FROM users WHERE name = %s", (username,))

// ✅ C# — SqlCommand with parameters
SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
cmd.Parameters.AddWithValue("@id", userId);

// ✅ Java — PreparedStatement with parameters
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE email = ?");
ps.setString(1, email);
*/
