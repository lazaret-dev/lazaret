// Severity order and type names, and the two whole-text SQL rules the SQL
// pass (sql.js scanSqlNowhere, twin of core.scan_sql_nowhere) fires: their
// pattern text copied verbatim from lazaret.scanner.core's TEXT_RULES and
// compiled with Python `re` semantics by pyRe(). Every other rule of core's
// RULES and TEXT_RULES is the native engine's since 0.1.9 (../lib/native.js
// scanRules and scanDependencyFile: the engine's rule pack holds core's own
// tables).

import { pyRe } from "../lib/pycompat.js";

export const SEV_ORDER = {BLOCKER:0, CRITICAL:1, MAJOR:2, MINOR:3, INFO:4};
export const TYPES = {VULN:"Vulnerability", HOTSPOT:"Security Hotspot", BUG:"Bug", SMELL:"Code Smell"};

// DELETE and UPDATE without WHERE: the statement heads, found in one linear pass (sql.js)
export const NOWHERE_RULES = [
{
id:"SQL-DELETE-NOWHERE", name:"DELETE without WHERE", type:"BUG", sev:"MAJOR", langs:["sql"],
 re:pyRe("\\bDELETE\\s+FROM\\s+[\\w.\\\"\\[\\]`]+", "i"),
 nowhere:true, // fired by scanSqlNowhere (sql.js), linear
 msg:"DELETE has no WHERE clause — it removes every row.",
 why:"An unqualified DELETE wipes the whole table; usually a mistake outside teardown scripts.",
 fix:"Add a WHERE clause, or use TRUNCATE deliberately if a full wipe is intended.",
 ref:"CWE-665",
},
{
id:"SQL-UPDATE-NOWHERE", name:"UPDATE without WHERE", type:"BUG", sev:"MAJOR", langs:["sql"],
 re:pyRe("\\bUPDATE\\s+[\\w.\\\"\\[\\]`]+\\s+SET\\b", "i"),
 nowhere:true,
 msg:"UPDATE has no WHERE clause — it changes every row.",
 why:"An unqualified UPDATE rewrites the entire table.",
 fix:"Add a WHERE clause to scope the update.",
 ref:"CWE-665",
},
];
