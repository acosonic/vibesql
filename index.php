<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

session_start();

// Generate a per-session CSRF token once
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// ─────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────
function db_connect(string $host, string $user, string $pass, string $db = ''): mysqli|false {
    $m = @new mysqli($host, $user, $pass, $db);
    if ($m->connect_errno) return false;
    $m->set_charset('utf8mb4');
    return $m;
}

function get_databases(string $host, string $user, string $pass): array {
    $m = db_connect($host, $user, $pass);
    if (!$m) return [];
    $res = $m->query("SHOW DATABASES");
    $out = [];
    while ($row = $res->fetch_row()) {
        if (!in_array($row[0], ['information_schema','performance_schema','sys','mysql']))
            $out[] = $row[0];
    }
    $m->close();
    return $out;
}

function get_schema(string $host, string $user, string $pass, string $db): array {
    $m = db_connect($host, $user, $pass, $db);
    if (!$m) return [];
    $res = $m->query("SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, COLUMN_KEY, IS_NULLABLE
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = '" . $m->real_escape_string($db) . "'
        ORDER BY TABLE_NAME, ORDINAL_POSITION");
    $schema = [];
    while ($row = $res->fetch_assoc())
        $schema[$row['TABLE_NAME']][] = $row;
    $m->close();
    return $schema;
}

function schema_to_text(array $schema, string $db): string {
    $lines = ["Database: `{$db}`\n"];
    foreach ($schema as $table => $cols) {
        $lines[] = "Table: `{$table}`";
        foreach ($cols as $c) {
            $flags = [];
            if ($c['COLUMN_KEY'] === 'PRI') $flags[] = 'PRIMARY KEY';
            if ($c['COLUMN_KEY'] === 'UNI') $flags[] = 'UNIQUE';
            if ($c['IS_NULLABLE'] === 'NO')  $flags[] = 'NOT NULL';
            $lines[] = '  ' . $c['COLUMN_NAME'] . ' ' . $c['COLUMN_TYPE']
                      . ($flags ? '  -- ' . implode(', ', $flags) : '');
        }
        $lines[] = '';
    }
    return implode("\n", $lines);
}

function sql_safety_check(string $sql): string {
    $c = preg_replace('/\/\*.*?\*\//s', ' ', $sql);
    $c = preg_replace('/--[^\n]*/', ' ', $c);
    $c = preg_replace('/\s+/', ' ', strtoupper($c));
    $rules = [
        'INTO\s+OUTFILE'    => 'INTO OUTFILE – writing files to disk is not allowed',
        'INTO\s+DUMPFILE'   => 'INTO DUMPFILE – writing files to disk is not allowed',
        'LOAD\s+DATA'       => 'LOAD DATA – reading files from disk is not allowed',
        'LOAD_FILE\s*\('    => 'LOAD_FILE() – reading files from disk is not allowed',
        'CREATE\s+FUNCTION' => 'CREATE FUNCTION – UDF creation is not allowed',
        'DROP\s+FUNCTION'   => 'DROP FUNCTION – not allowed',
        'SYS_EXEC\s*\('     => 'sys_exec() – OS command execution is not allowed',
        'SYS_EVAL\s*\('     => 'sys_eval() – OS command execution is not allowed',
    ];
    foreach ($rules as $pat => $msg)
        if (preg_match('/' . $pat . '/', $c)) return $msg;
    return '';
}

function ask_llm(string $key, string $model, string $prompt, array $schema, string $db): array {
    $schemaText = schema_to_text($schema, $db);
    $system = "You are a MySQL query assistant for database `{$db}`.\n\nSCHEMA:\n{$schemaText}\n"
        . "Respond ONLY with raw JSON (no markdown): {\"sql\":\"...\",\"explanation\":\"one sentence\"}\n"
        . "Rules: valid MySQL 8 syntax, exact column/table names, LIMIT 200 on SELECT unless user specifies, "
        . "never DROP/TRUNCATE/ALTER unless explicitly asked.";

    $payload = json_encode([
        'model'      => $model,
        'max_tokens' => 1024,
        'system'     => $system,
        'messages'   => [['role' => 'user', 'content' => $prompt]],
    ]);

    $ctx = stream_context_create(['http' => [
        'method'        => 'POST',
        'header'        => "Content-Type: application/json\r\nx-api-key: {$key}\r\nanthropic-version: 2023-06-01",
        'content'       => $payload,
        'timeout'       => 30,
        'ignore_errors' => true,
    ]]);

    $resp = @file_get_contents('https://api.anthropic.com/v1/messages', false, $ctx);
    if ($resp === false) return ['error' => 'API request failed (check network)'];

    $data = json_decode($resp, true);
    if (!empty($data['error'])) return ['error' => $data['error']['message'] ?? 'API error'];

    $text = preg_replace(['/^```(?:json)?\s*/i', '/\s*```$/'], '', trim($data['content'][0]['text'] ?? ''));
    $parsed = json_decode($text, true);
    if (!$parsed || !isset($parsed['sql'])) return ['error' => 'Invalid LLM response', 'raw' => $text];
    return $parsed;
}

// ─────────────────────────────────────────────
//  JSON API  (called via fetch from JS)
// ─────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['_api'])) {
    header('Content-Type: application/json; charset=utf-8');

    // CSRF check — rejects any request not originating from this page
    $tok = $_POST['_csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $tok)) {
        echo json_encode(['ok' => false, 'error' => 'Invalid CSRF token. Reload the page.']);
        exit;
    }

    $host   = trim($_POST['host']   ?? '');
    $user   = trim($_POST['user']   ?? '');
    $pass   =      $_POST['pass']   ?? '';
    $db     = trim($_POST['db']     ?? '');
    $apiKey = trim($_POST['apiKey'] ?? '');
    $model  = trim($_POST['model']  ?? 'claude-haiku-4-5-20251001');
    $action =      $_POST['action'] ?? '';

    switch ($action) {

        case 'test_connection':
            $m = db_connect($host, $user, $pass);
            if (!$m) { echo json_encode(['ok' => false, 'error' => 'Connection failed. Check host, user and password.']); break; }
            $dbs = get_databases($host, $user, $pass);
            $m->close();
            echo json_encode(['ok' => true, 'databases' => $dbs]);
            break;

        case 'get_schema':
            if (!$db) { echo json_encode(['ok' => false, 'error' => 'No database selected']); break; }
            echo json_encode(['ok' => true, 'schema' => get_schema($host, $user, $pass, $db)]);
            break;

        case 'query':
            $sql = trim($_POST['sql'] ?? '');
            if (!$sql) { echo json_encode(['ok' => false, 'error' => 'Empty query']); break; }
            $err = sql_safety_check($sql);
            if ($err) { echo json_encode(['ok' => false, 'error' => 'Blocked: ' . $err]); break; }
            $m = db_connect($host, $user, $pass, $db);
            if (!$m) { echo json_encode(['ok' => false, 'error' => 'Cannot connect to database']); break; }
            $res = $m->query($sql);
            if ($res === false) {
                echo json_encode(['ok' => false, 'error' => $m->error]);
            } elseif ($res === true) {
                echo json_encode(['ok' => true, 'type' => 'write', 'affected' => $m->affected_rows]);
            } else {
                $cols = array_column($res->fetch_fields(), 'name');
                $rows = [];
                while ($row = $res->fetch_row()) $rows[] = $row;
                echo json_encode(['ok' => true, 'type' => 'select', 'columns' => $cols, 'rows' => $rows]);
            }
            $m->close();
            break;

        case 'ask_ai':
            $prompt = trim($_POST['prompt'] ?? '');
            if (!$prompt)  { echo json_encode(['ok' => false, 'error' => 'Empty prompt']); break; }
            if (!$apiKey)  { echo json_encode(['ok' => false, 'error' => 'Anthropic API key not set']); break; }
            if (!$db)      { echo json_encode(['ok' => false, 'error' => 'No database selected']); break; }
            $schema = get_schema($host, $user, $pass, $db);
            $r = ask_llm($apiKey, $model, $prompt, $schema, $db);
            echo json_encode(!empty($r['error'])
                ? ['ok' => false, 'error' => $r['error']]
                : ['ok' => true, 'sql' => $r['sql'], 'explanation' => $r['explanation'] ?? '']);
            break;

        default:
            echo json_encode(['ok' => false, 'error' => 'Unknown action']);
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VibeSql</title>
<style>
/* ── theme variables ─────────────────────────── */
:root {
  --bg0:#f5f6f8;--bg1:#ffffff;--bg2:#f0f2f5;--bg3:#e8eaed;
  --line:#dde1e7;--dim:#adb5bd;--muted:#6c757d;--body:#495057;
  --text:#212529;--hi:#0d1117;
  --green:#16a34a;--amber:#d97706;--red:#dc2626;
  --cyan:#0891b2;--pur:#7c3aed;--accent:#2563eb;--ai:#7c3aed;
  --shadow:0 1px 3px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.06);
  --shadow-lg:0 10px 25px rgba(0,0,0,.12),0 4px 10px rgba(0,0,0,.08);
}
[data-theme="dark"] {
  --bg0:#0d0f12;--bg1:#13161b;--bg2:#1b1f27;--bg3:#242933;
  --line:#2a2f3d;--dim:#4a5168;--muted:#6b7591;--body:#9aa3bc;
  --text:#c8d0e7;--hi:#e8f0ff;
  --green:#4ade80;--amber:#fbbf24;--red:#f87171;
  --cyan:#22d3ee;--pur:#a78bfa;--accent:#3b82f6;--ai:#8b5cf6;
  --shadow:0 1px 3px rgba(0,0,0,.3),0 1px 2px rgba(0,0,0,.2);
  --shadow-lg:0 10px 25px rgba(0,0,0,.5),0 4px 10px rgba(0,0,0,.3);
}

/* ── reset ───────────────────────────────────── */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{background:var(--bg0);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",sans-serif;font-size:13px;line-height:1.5;display:flex;flex-direction:column;min-height:100vh;overflow-x:hidden;transition:background .2s,color .2s}

/* ── header ──────────────────────────────────── */
header{height:44px;background:var(--bg1);border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 16px;gap:12px;flex-shrink:0;position:sticky;top:0;z-index:100;box-shadow:var(--shadow)}
.logo{font-family:"JetBrains Mono","Fira Code",Consolas,monospace;font-size:14px;font-weight:700;color:var(--hi);display:flex;align-items:center;gap:6px;white-space:nowrap}
.logo-dot{color:var(--accent)}
.db-pill{display:flex;align-items:center;gap:5px;background:var(--bg2);border:1px solid var(--line);border-radius:20px;padding:3px 10px 3px 8px;font-family:monospace;font-size:11px;color:var(--cyan);cursor:pointer;transition:border-color .15s}
.db-pill:hover{border-color:var(--accent)}
.db-selector{display:flex;align-items:center;gap:6px}
.db-selector select{background:var(--bg2);border:1px solid var(--line);border-radius:5px;color:var(--text);font-size:12px;font-family:monospace;padding:4px 8px;cursor:pointer;outline:none;transition:border-color .15s}
.db-selector select:focus{border-color:var(--accent)}
.header-gap{flex:1}
.icon-btn{background:none;border:1px solid var(--line);border-radius:6px;color:var(--muted);cursor:pointer;padding:5px 7px;line-height:0;transition:all .15s;display:flex;align-items:center;gap:5px}
.icon-btn:hover{border-color:var(--accent);color:var(--text)}
.icon-btn span{font-size:11px;font-weight:500}

/* ── workspace ───────────────────────────────── */
.workspace{display:flex;flex:1;overflow:hidden;height:calc(100vh - 44px)}

/* ── sidebar ─────────────────────────────────── */
.sidebar{width:260px;background:var(--bg1);border-right:1px solid var(--line);display:flex;flex-direction:column;flex-shrink:0;overflow:hidden;transition:width .16s}
.sidebar.collapsed{width:36px}
.sidebar-hdr{height:38px;display:flex;align-items:center;justify-content:space-between;padding:0 10px;border-bottom:1px solid var(--line);flex-shrink:0}
.sidebar-title{font-size:10px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--dim);white-space:nowrap;overflow:hidden}
.sidebar.collapsed .sidebar-title{opacity:0}
.sidebar-toggle{background:none;border:none;color:var(--dim);cursor:pointer;padding:2px;border-radius:3px;line-height:0;transition:color .15s}
.sidebar-toggle:hover{color:var(--text)}
.sidebar-body{flex:1;overflow-y:auto;overflow-x:hidden;padding:6px 0}
.sidebar.collapsed .sidebar-body{opacity:0;pointer-events:none}
.sidebar-body::-webkit-scrollbar{width:4px}
.sidebar-body::-webkit-scrollbar-thumb{background:var(--line);border-radius:4px}
.table-node{margin-bottom:2px}
.table-btn{display:flex;align-items:center;gap:6px;width:100%;padding:5px 12px;background:none;border:none;color:var(--body);font-family:monospace;font-size:11.5px;cursor:pointer;text-align:left;transition:background .15s,color .15s;white-space:nowrap;overflow:hidden}
.table-btn:hover{background:var(--bg2);color:var(--hi)}
.table-btn .arr{color:var(--dim);transition:transform .15s;flex-shrink:0}
.table-btn.open .arr{transform:rotate(90deg)}
.tbl-icon{color:var(--amber);flex-shrink:0}
.tbl-name{flex:1;overflow:hidden;text-overflow:ellipsis}
.col-cnt{font-size:10px;color:var(--dim);margin-left:auto;flex-shrink:0}
.col-list{display:none;padding:0 0 4px 0}
.col-list.open{display:block}
.col-row{display:flex;align-items:center;gap:6px;padding:3px 14px 3px 32px;font-family:monospace;font-size:10.5px;color:var(--muted);white-space:nowrap;overflow:hidden}
.col-row:hover{background:var(--bg2);color:var(--body)}
.col-name{flex:1;overflow:hidden;text-overflow:ellipsis}
.col-type{color:var(--pur);font-size:10px;flex-shrink:0}
.key-pri{color:var(--amber)}
.key-mul{color:var(--cyan)}
.no-schema{padding:20px 12px;font-size:11px;color:var(--dim);text-align:center;font-family:monospace}

/* ── main panel ──────────────────────────────── */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;background:var(--bg0)}

/* section label */
.sec-label{font-size:10px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--dim);margin-bottom:8px;display:flex;align-items:center;gap:6px}
.badge{background:rgba(124,58,237,.12);border:1px solid rgba(124,58,237,.25);color:var(--pur);border-radius:3px;padding:1px 6px;font-size:9px;letter-spacing:.08em}
[data-theme="dark"] .badge{background:rgba(139,92,246,.15);border-color:rgba(139,92,246,.3)}

/* ── AI section ──────────────────────────────── */
.ai-section{padding:12px 16px;border-bottom:2px solid var(--line);background:var(--bg1);flex-shrink:0}
.ai-wrap{border:1px solid var(--line);border-radius:6px;overflow:hidden;transition:border-color .15s,box-shadow .15s}
.ai-wrap:focus-within{border-color:var(--ai);box-shadow:0 0 0 3px rgba(124,58,237,.1)}
[data-theme="dark"] .ai-wrap:focus-within{box-shadow:0 0 0 3px rgba(139,92,246,.12)}
.ai-input{width:100%;background:var(--bg0);color:var(--hi);font-size:13px;line-height:1.6;padding:10px 14px;border:none;outline:none;resize:none;caret-color:var(--ai)}
.ai-input::placeholder{color:var(--dim)}
.ai-footer{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:8px}
.btn-ask{display:flex;align-items:center;gap:7px;background:var(--ai);border:none;border-radius:6px;color:#fff;font-size:12.5px;font-weight:600;padding:7px 18px;cursor:pointer;transition:opacity .15s,transform 80ms}
.btn-ask:hover{opacity:.88}
.btn-ask:active{transform:scale(.97)}
.btn-ask:disabled{opacity:.5;pointer-events:none}
.ai-explain{display:flex;align-items:flex-start;gap:8px;margin-top:10px;padding:8px 12px;background:rgba(124,58,237,.07);border:1px solid rgba(124,58,237,.18);border-radius:6px;font-size:12px;color:#6d28d9;animation:fadeIn .2s}
[data-theme="dark"] .ai-explain{background:rgba(139,92,246,.08);border-color:rgba(139,92,246,.2);color:#c4b5fd}

/* ── SQL section ─────────────────────────────── */
.sql-section{padding:12px 16px;border-bottom:1px solid var(--line);background:var(--bg1);flex-shrink:0}
.sql-wrap{border:1px solid var(--line);border-radius:6px;overflow:hidden;transition:border-color .15s,box-shadow .15s}
.sql-wrap:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px rgba(37,99,235,.1)}
[data-theme="dark"] .sql-wrap:focus-within{box-shadow:0 0 0 3px rgba(59,130,246,.12)}
.sql-input{width:100%;min-height:100px;max-height:260px;background:var(--bg0);color:var(--hi);font-family:"JetBrains Mono","Fira Code",Consolas,monospace;font-size:13px;line-height:1.65;padding:12px 14px;border:none;outline:none;resize:vertical;caret-color:var(--accent);tab-size:2}
.sql-input::placeholder{color:var(--dim)}
.sql-input::-webkit-scrollbar{width:4px}
.sql-input::-webkit-scrollbar-thumb{background:var(--line);border-radius:4px}
.sql-footer{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:8px}
.hints{font-size:10.5px;color:var(--dim)}
.hints kbd{background:var(--bg3);border:1px solid var(--line);border-radius:3px;padding:1px 5px;font-size:10px;color:var(--muted)}
.btn-run{display:flex;align-items:center;gap:7px;background:var(--accent);border:none;border-radius:6px;color:#fff;font-size:12.5px;font-weight:600;padding:7px 18px;cursor:pointer;transition:opacity .15s,transform 80ms}
.btn-run:hover{opacity:.88}
.btn-run:active{transform:scale(.97)}
.btn-run:disabled{opacity:.5;pointer-events:none}

/* ── message bar ─────────────────────────────── */
.msg-bar{display:flex;align-items:center;gap:8px;padding:9px 16px;font-family:monospace;font-size:12px;flex-shrink:0;animation:fadeIn .2s}
.msg-bar.ok   {background:rgba(22,163,74,.07);color:var(--green);border-bottom:1px solid rgba(22,163,74,.2)}
.msg-bar.error{background:rgba(220,38,38,.07);color:var(--red);  border-bottom:1px solid rgba(220,38,38,.2)}
[data-theme="dark"] .msg-bar.ok   {background:rgba(74,222,128,.07);border-color:rgba(74,222,128,.15)}
[data-theme="dark"] .msg-bar.error{background:rgba(248,113,113,.08);border-color:rgba(248,113,113,.15)}

/* ── results ─────────────────────────────────── */
.results{flex:1;overflow:auto;overflow-x:auto}
.results::-webkit-scrollbar{width:10px;height:10px}
.results::-webkit-scrollbar-track{background:var(--bg2)}
.results::-webkit-scrollbar-thumb{background:var(--dim);border-radius:6px;border:2px solid var(--bg2)}
.results::-webkit-scrollbar-thumb:hover{background:var(--muted)}
.results::-webkit-scrollbar-corner{background:var(--bg2)}
.result-wrap{min-width:max-content}
table.rt{width:max-content;min-width:100%;border-collapse:collapse;font-family:monospace;font-size:12px}
table.rt thead tr{background:var(--bg2);border-bottom:2px solid var(--line);position:sticky;top:0;z-index:10}
table.rt th{padding:9px 14px;text-align:left;font-size:10.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);white-space:nowrap;border-right:1px solid var(--line)}
table.rt th.sortable{cursor:pointer;user-select:none}
table.rt th.sortable:hover{color:var(--text)}
table.rt th.sort-active{color:var(--accent)}
table.rt th:last-child{border-right:none}
table.rt tbody tr{border-bottom:1px solid var(--line);transition:background .15s}
table.rt tbody tr:hover{background:var(--bg2)}
table.rt tbody tr:nth-child(even){background:rgba(0,0,0,.02)}
[data-theme="dark"] table.rt tbody tr:nth-child(even){background:rgba(27,31,39,.4)}
table.rt td{padding:7px 14px;color:var(--body);white-space:nowrap;max-width:340px;overflow:hidden;text-overflow:ellipsis;border-right:1px solid var(--line);vertical-align:middle}
table.rt td:last-child{border-right:none}
.null-v{color:var(--dim);font-style:italic}
.empty-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;color:var(--dim);gap:10px;padding:40px;font-size:12.5px}
.empty-state svg{opacity:.25}

/* ── DB picker ───────────────────────────────── */
.picker-wrap{flex:1;display:flex;align-items:center;justify-content:center;padding:40px}
.picker-card{background:var(--bg1);border:1px solid var(--line);border-radius:10px;padding:32px 36px;width:100%;max-width:400px;text-align:center;box-shadow:var(--shadow)}
.picker-card h2{font-size:17px;font-weight:700;color:var(--hi);margin-bottom:6px}
.picker-card p{font-size:12px;color:var(--muted);margin-bottom:20px}
.db-list{display:flex;flex-direction:column;gap:6px}
.db-btn{display:flex;align-items:center;gap:10px;width:100%;padding:10px 14px;background:var(--bg2);border:1px solid var(--line);border-radius:6px;color:var(--text);font-family:monospace;font-size:13px;cursor:pointer;transition:all .15s;text-align:left}
.db-btn:hover{border-color:var(--accent);color:var(--hi)}
.db-btn svg{color:var(--amber);flex-shrink:0}

/* ── modal overlay ───────────────────────────── */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px;backdrop-filter:blur(3px);animation:fadeIn .15s}
.overlay.hidden{display:none}
.modal{background:var(--bg1);border:1px solid var(--line);border-radius:10px;width:100%;max-width:460px;box-shadow:var(--shadow-lg);animation:slideUp .2s}
.modal-hdr{display:flex;align-items:center;justify-content:space-between;padding:18px 20px 0}
.modal-hdr h2{font-size:16px;font-weight:700;color:var(--hi)}
.modal-close{background:none;border:none;color:var(--muted);cursor:pointer;font-size:18px;line-height:1;padding:2px 6px;border-radius:4px;transition:color .15s}
.modal-close:hover{color:var(--text)}
.modal-body{padding:18px 20px}
.field-group{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px}
.field-group.full{grid-template-columns:1fr}
.field{display:flex;flex-direction:column;gap:4px}
.field label{font-size:11px;font-weight:600;color:var(--muted);letter-spacing:.04em;text-transform:uppercase}
.field input,.field select{background:var(--bg0);border:1px solid var(--line);border-radius:6px;color:var(--hi);font-size:13px;font-family:monospace;padding:8px 10px;outline:none;transition:border-color .15s}
.field input:focus,.field select:focus{border-color:var(--accent)}
.field input::placeholder{color:var(--dim)}
.modal-sep{border:none;border-top:1px solid var(--line);margin:14px 0}
.modal-ftr{padding:0 20px 18px;display:flex;flex-direction:column;gap:8px}
.btn-connect{width:100%;background:var(--accent);border:none;border-radius:6px;color:#fff;font-size:13.5px;font-weight:600;padding:10px;cursor:pointer;transition:opacity .15s}
.btn-connect:hover{opacity:.88}
.btn-connect:disabled{opacity:.5;pointer-events:none}
.conn-status{font-size:12px;font-family:monospace;min-height:18px;text-align:center}
.conn-status.ok{color:var(--green)}
.conn-status.error{color:var(--red)}
.conn-status.info{color:var(--muted)}

@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes slideUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
@keyframes spin{to{transform:rotate(360deg)}}
.spin{display:inline-block;width:12px;height:12px;border:2px solid rgba(255,255,255,.35);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite}
</style>
</head>
<body>

<header>
  <div class="logo">
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none">
      <ellipse cx="8" cy="4.5" rx="5.5" ry="2" stroke="currentColor" stroke-width="1.4"/>
      <path d="M2.5 4.5v7c0 1.1 2.46 2 5.5 2s5.5-.9 5.5-2v-7" stroke="currentColor" stroke-width="1.4"/>
      <path d="M2.5 8c0 1.1 2.46 2 5.5 2s5.5-.9 5.5-2" stroke="currentColor" stroke-width="1.2" stroke-dasharray="2 1.5"/>
    </svg>
    VibeSql<span class="logo-dot">.</span>
  </div>

  <div id="dbPill" class="db-pill" style="display:none" title="Switch database">
    <svg width="11" height="11" viewBox="0 0 16 16" fill="none"><ellipse cx="8" cy="4" rx="5" ry="1.8" stroke="currentColor" stroke-width="1.4"/><path d="M3 4v8c0 1 2.24 1.8 5 1.8s5-.8 5-1.8V4" stroke="currentColor" stroke-width="1.4"/></svg>
    <span id="dbPillName"></span>
  </div>

  <div id="dbSelectorWrap" class="db-selector" style="display:none">
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" style="color:var(--muted)"><ellipse cx="8" cy="4" rx="5" ry="1.8" stroke="currentColor" stroke-width="1.3"/><path d="M3 4v8c0 1 2.24 1.8 5 1.8s5-.8 5-1.8V4" stroke="currentColor" stroke-width="1.3"/></svg>
    <select id="dbSelect" onchange="switchDb(this.value)"></select>
  </div>

  <div class="header-gap"></div>

  <button class="icon-btn" id="themeBtn" onclick="toggleTheme()" title="Toggle theme">
    <svg id="themeIcon" width="14" height="14" viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="3.5" stroke="currentColor" stroke-width="1.4"/>
      <path d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3.1 3.1l1 1M11.9 11.9l1 1M3.1 12.9l1-1M11.9 4.1l1-1" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
    </svg>
  </button>

  <button class="icon-btn" onclick="openSettings()" title="Settings">
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="2.5" stroke="currentColor" stroke-width="1.4"/>
      <path d="M8 1v1M8 14v1M1 8h1M14 8h1M3.1 3.1l.7.7M12.2 12.2l.7.7M3.1 12.9l.7-.7M12.2 3.8l.7-.7" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
    </svg>
    <span>Settings</span>
  </button>
</header>

<!-- ── SETTINGS MODAL ─────────────────────────── -->
<div class="overlay" id="overlay">
  <div class="modal">
    <div class="modal-hdr">
      <h2>Connection Settings</h2>
      <button class="modal-close" id="modalClose" onclick="closeSettings()">✕</button>
    </div>
    <div class="modal-body">
      <div class="field-group">
        <div class="field">
          <label>MySQL Host</label>
          <input type="text" id="cfgHost" placeholder="localhost" autocomplete="off">
        </div>
        <div class="field">
          <label>Port</label>
          <input type="text" id="cfgPort" placeholder="3306" autocomplete="off">
        </div>
      </div>
      <div class="field-group">
        <div class="field">
          <label>User</label>
          <input type="text" id="cfgUser" placeholder="root" autocomplete="off">
        </div>
        <div class="field">
          <label>Password</label>
          <input type="password" id="cfgPass" placeholder="••••••••" autocomplete="new-password">
        </div>
      </div>
      <hr class="modal-sep">
      <div class="field-group full">
        <div class="field">
          <label>Anthropic API Key <span style="color:var(--dim);font-weight:400;text-transform:none">(optional – for AI queries)</span></label>
          <input type="password" id="cfgApiKey" placeholder="sk-ant-..." autocomplete="new-password">
        </div>
      </div>
      <div class="field-group full" style="margin-top:10px">
        <div class="field">
          <label>Claude Model</label>
          <select id="cfgModel">
            <option value="claude-haiku-4-5-20251001">claude-haiku-4-5 (fast, cheap)</option>
            <option value="claude-sonnet-4-6">claude-sonnet-4-6 (smarter)</option>
          </select>
        </div>
      </div>
    </div>
    <div class="modal-ftr">
      <div class="conn-status info" id="connStatus">Enter your MySQL credentials above.</div>
      <button class="btn-connect" id="btnConnect" onclick="saveAndConnect()">
        Test Connection &amp; Save
      </button>
      <div style="text-align:center">
        <button onclick="resetTheme()" style="background:none;border:none;color:var(--dim);font-size:11px;cursor:pointer;text-decoration:underline;padding:2px" title="Follow OS light/dark preference">Reset theme to system default</button>
      </div>
    </div>
  </div>
</div>

<!-- ── WORKSPACE ──────────────────────────────── -->
<div class="workspace" id="workspace" style="display:none">

  <!-- sidebar -->
  <aside class="sidebar" id="sidebar">
    <div class="sidebar-hdr">
      <span class="sidebar-title">Schema</span>
      <button class="sidebar-toggle" id="sidebarToggle">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M10 3L6 8l4 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" id="sidebarArrow"/></svg>
      </button>
    </div>
    <div class="sidebar-body" id="schemaTree"><div class="no-schema">Select a database</div></div>
  </aside>

  <!-- main -->
  <main class="main">

    <!-- AI -->
    <div class="ai-section">
      <div class="sec-label">
        <svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M8 1.5a6.5 6.5 0 110 13 6.5 6.5 0 010-13z" stroke="currentColor" stroke-width="1.4"/><path d="M8 5v5M8 11.5v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
        Ask AI <span class="badge">Claude</span>
      </div>
      <div class="ai-wrap">
        <textarea id="aiInput" class="ai-input" rows="2"
          placeholder="e.g. Show all users who signed up this week, sorted by name..."
          spellcheck="false"></textarea>
      </div>
      <div class="ai-footer">
        <span class="hints"><kbd>Ctrl</kbd>+<kbd>↵</kbd> to send</span>
        <button class="btn-ask" id="btnAsk" onclick="doAsk()">
          <svg width="13" height="13" viewBox="0 0 16 16" fill="none"><path d="M2 2l12 6-12 6V9.5l8-1.5-8-1.5V2z" fill="currentColor"/></svg>
          Generate SQL
        </button>
      </div>
      <div class="ai-explain" id="aiExplain" style="display:none">
        <svg width="13" height="13" viewBox="0 0 16 16" fill="none" style="flex-shrink:0;margin-top:1px"><path d="M8 1.5a6.5 6.5 0 110 13 6.5 6.5 0 010-13z" stroke="currentColor" stroke-width="1.4"/><path d="M8 7v4M8 5.5v.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>
        <span id="aiExplainText"></span>
      </div>
    </div>

    <!-- SQL -->
    <div class="sql-section">
      <div class="sec-label">
        <svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M4 5l-2 3 2 3M12 5l2 3-2 3M9 3l-2 10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
        SQL Query
      </div>
      <div class="sql-wrap">
        <textarea id="sqlInput" class="sql-input"
          placeholder="SELECT * FROM users LIMIT 20;&#10;&#10;-- Ctrl+Enter to run"
          spellcheck="false" autocomplete="off" autocorrect="off"></textarea>
      </div>
      <div class="sql-footer">
        <span class="hints"><kbd>Ctrl</kbd>+<kbd>Enter</kbd> to run</span>
        <button class="btn-run" id="btnRun" onclick="doQuery()">
          <svg width="13" height="13" viewBox="0 0 16 16" fill="none"><path d="M4 2.5l9 5.5-9 5.5V2.5z" fill="currentColor"/></svg>
          Run
        </button>
      </div>
    </div>

    <!-- msg -->
    <div id="msgBar" style="display:none" class="msg-bar"></div>

    <!-- results -->
    <div class="results" id="resultsArea">
      <div class="empty-state">
        <svg width="40" height="40" viewBox="0 0 40 40" fill="none"><rect x="4" y="4" width="32" height="32" rx="4" stroke="currentColor" stroke-width="1.5"/><path d="M4 14h32M14 14v22M4 24h32" stroke="currentColor" stroke-width="1.2" stroke-dasharray="3 2"/></svg>
        <span>Run a query to see results</span>
      </div>
    </div>

  </main>
</div>

<!-- ── DB PICKER ──────────────────────────────── -->
<div id="pickerArea" class="picker-wrap" style="display:none">
  <div class="picker-card">
    <div style="font-size:28px;margin-bottom:14px">🗄️</div>
    <h2>Select a database</h2>
    <p id="pickerSub"></p>
    <div class="db-list" id="dbList"></div>
  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf_token) ?>;

// ── State ─────────────────────────────────────
// Non-sensitive (host, user, model, db, theme) → localStorage
// Sensitive (pass, apiKey) → sessionStorage (cleared when tab closes)
const LS = {
  get:    k => localStorage.getItem('vibesql_' + k),
  set:    (k, v) => localStorage.setItem('vibesql_' + k, v),
  del:    k => localStorage.removeItem('vibesql_' + k),
};
const SS = {
  get:    k => sessionStorage.getItem('vibesql_' + k),
  set:    (k, v) => sessionStorage.setItem('vibesql_' + k, v),
  del:    k => sessionStorage.removeItem('vibesql_' + k),
};

let state = {
  host: '', user: '', pass: '', apiKey: '', model: '',
  db: '', databases: [], schema: {},
};

// ── API calls ────────────────────────────────
async function api(action, extra = {}) {
  const body = new FormData();
  body.append('_api',   '1');
  body.append('_csrf',  CSRF);
  body.append('action', action);
  body.append('host',   state.host);
  body.append('user',   state.user);
  body.append('pass',   state.pass);
  body.append('db',     state.db);
  body.append('apiKey', state.apiKey);
  body.append('model',  state.model);
  for (const [k, v] of Object.entries(extra)) body.append(k, v);
  const r = await fetch('', { method: 'POST', body });
  return r.json();
}

// ── Settings ──────────────────────────────────
function openSettings() {
  document.getElementById('cfgHost').value   = state.host   || LS.get('host')  || '';
  document.getElementById('cfgPort').value   = LS.get('port') || '';
  document.getElementById('cfgUser').value   = state.user   || LS.get('user')  || '';
  // Sensitive fields: read from sessionStorage (will be empty after tab close)
  document.getElementById('cfgPass').value   = state.pass   || SS.get('pass')   || '';
  document.getElementById('cfgApiKey').value = state.apiKey || SS.get('apiKey') || '';
  document.getElementById('cfgModel').value  = state.model  || LS.get('model')  || 'claude-haiku-4-5-20251001';
  setStatus('Enter your MySQL credentials above.', 'info');
  document.getElementById('overlay').classList.remove('hidden');
  document.getElementById('modalClose').style.display = state.host ? '' : 'none';
}

function closeSettings() {
  if (!state.host) return; // can't close without saving first
  document.getElementById('overlay').classList.add('hidden');
}

async function saveAndConnect() {
  const host   = document.getElementById('cfgHost').value.trim()   || 'localhost';
  const user   = document.getElementById('cfgUser').value.trim();
  const pass   = document.getElementById('cfgPass').value;
  const apiKey = document.getElementById('cfgApiKey').value.trim();
  const model  = document.getElementById('cfgModel').value;

  if (!user) { setStatus('User is required.', 'error'); return; }

  const btn = document.getElementById('btnConnect');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Connecting…';
  setStatus('Testing connection…', 'info');

  // temporarily use new creds for the test call
  const prev = { ...state };
  state.host = host; state.user = user; state.pass = pass;

  const r = await api('test_connection');
  if (!r.ok) {
    state.host = prev.host; state.user = prev.user; state.pass = prev.pass;
    setStatus(r.error, 'error');
    btn.disabled = false;
    btn.innerHTML = 'Test Connection &amp; Save';
    return;
  }

  // Non-sensitive → localStorage (persists across sessions)
  LS.set('host',  host);
  LS.set('user',  user);
  LS.set('model', model);
  // Sensitive → sessionStorage (cleared when tab/browser closes)
  SS.set('pass',   pass);
  SS.set('apiKey', apiKey);

  state.apiKey    = apiKey;
  state.model     = model;
  state.databases = r.databases;

  setStatus('Connected! ' + r.databases.length + ' database(s) found.', 'ok');
  btn.disabled = false;
  btn.innerHTML = 'Test Connection &amp; Save';

  setTimeout(() => {
    document.getElementById('overlay').classList.add('hidden');
    showDbPicker();
  }, 700);
}

function setStatus(msg, type) {
  const el = document.getElementById('connStatus');
  el.textContent = msg;
  el.className = 'conn-status ' + type;
}

// ── DB picker ─────────────────────────────────
function showDbPicker() {
  document.getElementById('workspace').style.display   = 'none';
  document.getElementById('pickerArea').style.display  = 'flex';
  document.getElementById('pickerSub').textContent =
    'Connected to ' + state.host + ' as ' + state.user;

  const list = document.getElementById('dbList');
  list.innerHTML = '';
  state.databases.forEach(db => {
    const btn = document.createElement('button');
    btn.className = 'db-btn';
    btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 16 16" fill="none"><ellipse cx="8" cy="4" rx="5" ry="1.8" stroke="currentColor" stroke-width="1.3"/><path d="M3 4v8c0 1 2.24 1.8 5 1.8s5-.8 5-1.8V4" stroke="currentColor" stroke-width="1.3"/><path d="M3 8c0 1 2.24 1.8 5 1.8s5-.8 5-1.8" stroke="currentColor" stroke-width="1.1"/></svg>${escH(db)}`;
    btn.onclick = () => selectDb(db);
    list.appendChild(btn);
  });
}

async function selectDb(db) {
  state.db = db;
  LS.set('db', db);
  document.getElementById('pickerArea').style.display = 'none';
  document.getElementById('workspace').style.display  = 'flex';
  updateDbHeader();
  await loadSchema(db);
}

async function switchDb(db) {
  state.db = db;
  LS.set('db', db);
  updateDbHeader();
  clearResults();
  SS.del('lastSql'); SS.del('lastPrompt');
  document.getElementById('sqlInput').value = '';
  document.getElementById('aiInput').value  = '';
  await loadSchema(db);
}

function updateDbHeader() {
  document.getElementById('dbPillName').textContent = state.db;
  document.getElementById('dbPill').style.display = state.db ? '' : 'none';

  // populate selector
  const sel = document.getElementById('dbSelect');
  sel.innerHTML = '';
  state.databases.forEach(db => {
    const o = document.createElement('option');
    o.value = db; o.textContent = db;
    if (db === state.db) o.selected = true;
    sel.appendChild(o);
  });
  document.getElementById('dbSelectorWrap').style.display =
    state.databases.length > 1 ? '' : 'none';
}

// ── Schema ────────────────────────────────────
async function loadSchema(db) {
  document.getElementById('schemaTree').innerHTML =
    '<div class="no-schema">Loading…</div>';
  const r = await api('get_schema', { db });
  if (!r.ok) {
    document.getElementById('schemaTree').innerHTML =
      '<div class="no-schema">Error loading schema</div>';
    return;
  }
  state.schema = r.schema;
  renderSchema(r.schema);
}

function renderSchema(schema) {
  const tree = document.getElementById('schemaTree');
  const tables = Object.keys(schema);
  if (!tables.length) {
    tree.innerHTML = '<div class="no-schema">No tables found</div>';
    return;
  }
  tree.innerHTML = tables.map(tbl => {
    const cols = schema[tbl];
    const colsHtml = cols.map(c => {
      let icon = `<svg width="10" height="10" viewBox="0 0 16 16" fill="none" style="color:var(--dim)"><circle cx="8" cy="8" r="3" stroke="currentColor" stroke-width="1.3"/></svg>`;
      if (c.COLUMN_KEY === 'PRI') icon = `<svg width="10" height="10" viewBox="0 0 16 16" fill="none" class="key-pri"><path d="M9.5 1.5a4 4 0 110 8 4 4 0 010-8zm-4 6.5L2 14.5M3.5 11L5 12.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>`;
      else if (c.COLUMN_KEY === 'MUL') icon = `<svg width="10" height="10" viewBox="0 0 16 16" fill="none" class="key-mul"><path d="M3 8h10M3 5h10M3 11h6" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>`;
      return `<div class="col-row">${icon}<span class="col-name">${escH(c.COLUMN_NAME)}</span><span class="col-type">${escH(c.COLUMN_TYPE)}</span></div>`;
    }).join('');
    return `<div class="table-node">
      <button class="table-btn" onclick="toggleTbl(this)">
        <span class="arr"><svg width="9" height="9" viewBox="0 0 9 9" fill="none"><path d="M2 1.5l3 3-3 3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg></span>
        <span class="tbl-icon"><svg width="12" height="12" viewBox="0 0 16 16" fill="none"><rect x="1.5" y="1.5" width="13" height="13" rx="1.5" stroke="currentColor" stroke-width="1.3"/><path d="M1.5 6h13M1.5 10h13M6 1.5v13" stroke="currentColor" stroke-width="1.1"/></svg></span>
        <span class="tbl-name">${escH(tbl)}</span>
        <span class="col-cnt">${cols.length}</span>
      </button>
      <div class="col-list">${colsHtml}</div>
    </div>`;
  }).join('');
}

function toggleTbl(btn) {
  btn.classList.toggle('open');
  btn.nextElementSibling.classList.toggle('open');
}

// ── Query ─────────────────────────────────────
async function doQuery() {
  const sql = document.getElementById('sqlInput').value.trim();
  if (!sql) return;
  setBtn('btnRun', true, '<span class="spin"></span> Running…');
  hideMsg();
  const r = await api('query', { sql });
  setBtn('btnRun', false, '<svg width="13" height="13" viewBox="0 0 16 16" fill="none"><path d="M4 2.5l9 5.5-9 5.5V2.5z" fill="currentColor"/></svg> Run');
  if (!r.ok) { showMsg(r.error, 'error'); clearResults(); return; }
  if (r.type === 'write') {
    showMsg('Query OK – ' + r.affected + ' row(s) affected.', 'ok');
    clearResults();
  } else {
    showMsg(r.rows.length + ' row(s) returned.', 'ok');
    renderTable(r.columns, r.rows);
  }
}

// ── Ask AI ────────────────────────────────────
async function doAsk() {
  const prompt = document.getElementById('aiInput').value.trim();
  if (!prompt) return;
  if (!state.apiKey) {
    showMsg('Anthropic API key not set. Open Settings to add it.', 'error');
    return;
  }
  if (!state.db) { showMsg('Select a database first.', 'error'); return; }
  setBtn('btnAsk', true, '<span class="spin"></span> Generating…');
  document.getElementById('aiExplain').style.display = 'none';
  const r = await api('ask_ai', { prompt });
  setBtn('btnAsk', false, '<svg width="13" height="13" viewBox="0 0 16 16" fill="none"><path d="M2 2l12 6-12 6V9.5l8-1.5-8-1.5V2z" fill="currentColor"/></svg> Generate SQL');
  if (!r.ok) { showMsg(r.error, 'error'); return; }
  document.getElementById('sqlInput').value = r.sql;
  if (r.explanation) {
    document.getElementById('aiExplainText').textContent = r.explanation;
    document.getElementById('aiExplain').style.display = 'flex';
  }
  hideMsg();
}

// ── Render table ──────────────────────────────
let sortState = { col: null, dir: 1 }; // dir: 1=asc, -1=desc
let lastCols = [], lastRows = [];

function renderTable(cols, rows, sortCol = null, sortDir = 1) {
  lastCols = cols; lastRows = rows;
  sortState = { col: sortCol, dir: sortDir };

  const sorted = sortCol === null ? rows : [...rows].sort((a, b) => {
    const av = a[sortCol] ?? '', bv = b[sortCol] ?? '';
    const an = parseFloat(av), bn = parseFloat(bv);
    const cmp = (!isNaN(an) && !isNaN(bn)) ? an - bn : String(av).localeCompare(String(bv));
    return cmp * sortDir;
  });

  const th = cols.map((c, i) => {
    const active = i === sortCol;
    const arrow  = active ? (sortDir === 1 ? ' ↑' : ' ↓') : '';
    return `<th class="sortable${active ? ' sort-active' : ''}" onclick="sortBy(${i})">${escH(c)}${arrow}</th>`;
  }).join('');

  const tb = sorted.map(row =>
    '<tr>' + row.map(v =>
      v === null ? '<td><span class="null-v">NULL</span></td>'
                : `<td>${escH(String(v))}</td>`
    ).join('') + '</tr>'
  ).join('');

  document.getElementById('resultsArea').innerHTML =
    `<div class="result-wrap"><table class="rt"><thead><tr>${th}</tr></thead><tbody>${tb}</tbody></table></div>`;
}

function sortBy(col) {
  const dir = sortState.col === col ? -sortState.dir : 1;
  renderTable(lastCols, lastRows, col, dir);
}

function clearResults() {
  document.getElementById('resultsArea').innerHTML =
    `<div class="empty-state">
      <svg width="40" height="40" viewBox="0 0 40 40" fill="none"><rect x="4" y="4" width="32" height="32" rx="4" stroke="currentColor" stroke-width="1.5"/><path d="M4 14h32M14 14v22M4 24h32" stroke="currentColor" stroke-width="1.2" stroke-dasharray="3 2"/></svg>
      <span>Run a query to see results</span>
    </div>`;
}

// ── Msg bar ───────────────────────────────────
function showMsg(text, type) {
  const bar = document.getElementById('msgBar');
  const icon = type === 'ok'
    ? `<svg width="13" height="13" viewBox="0 0 16 16" fill="none"><path d="M2.5 8.5l3.5 3.5 7.5-8" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`
    : `<svg width="13" height="13" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.4"/><path d="M8 5v4M8 11v.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>`;
  bar.className = 'msg-bar ' + type;
  bar.innerHTML = icon + escH(text);
  bar.style.display = 'flex';
}
function hideMsg() { document.getElementById('msgBar').style.display = 'none'; }

// ── Theme ─────────────────────────────────────
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  updateThemeIcon(theme);
}

function resetTheme() {
  LS.del('theme');
  const sysDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  applyTheme(sysDark ? 'dark' : 'light');
}

function toggleTheme() {
  // Once user manually picks, stop following system
  const html   = document.documentElement;
  const isDark = html.getAttribute('data-theme') === 'dark';
  const next   = isDark ? 'light' : 'dark';
  LS.set('theme', next);   // 'light' or 'dark' = manual override
  applyTheme(next);
}

function updateThemeIcon(theme) {
  const icon = document.getElementById('themeIcon');
  if (theme === 'dark') {
    // moon icon
    icon.innerHTML = `<path d="M13.5 10A6 6 0 016 2.5a6 6 0 100 11A6 6 0 0113.5 10z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>`;
  } else {
    // sun icon
    icon.innerHTML = `<circle cx="8" cy="8" r="3.5" stroke="currentColor" stroke-width="1.4"/><path d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3.1 3.1l1 1M11.9 11.9l1 1M3.1 12.9l1-1M11.9 4.1l1-1" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>`;
  }
}

// ── Sidebar ───────────────────────────────────
let sidebarCollapsed = false;
document.getElementById('sidebarToggle').addEventListener('click', () => {
  sidebarCollapsed = !sidebarCollapsed;
  document.getElementById('sidebar').classList.toggle('collapsed', sidebarCollapsed);
  document.getElementById('sidebarArrow').setAttribute('d',
    sidebarCollapsed ? 'M6 3l4 5-4 5' : 'M10 3L6 8l4 5');
});

// ── Persist inputs across refresh (sessionStorage) ────
document.getElementById('sqlInput').addEventListener('input', e => {
  SS.set('lastSql', e.target.value);
});
document.getElementById('aiInput').addEventListener('input', e => {
  SS.set('lastPrompt', e.target.value);
});

function restoreInputs() {
  const sql    = SS.get('lastSql');
  const prompt = SS.get('lastPrompt');
  if (sql)    document.getElementById('sqlInput').value = sql;
  if (prompt) document.getElementById('aiInput').value  = prompt;
}

// ── Keyboard shortcuts ────────────────────────
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    if (document.activeElement === document.getElementById('aiInput')) doAsk();
    else doQuery();
  }
  if (e.key === 'Escape') closeSettings();
});

// ── Utils ─────────────────────────────────────
function escH(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function setBtn(id, disabled, html) {
  const b = document.getElementById(id);
  b.disabled = disabled;
  b.innerHTML = html;
}

// ── Boot ──────────────────────────────────────
(function boot() {
  // Theme: use manual override if set, otherwise follow OS preference
  const saved  = LS.get('theme');
  const sysDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const theme  = saved || (sysDark ? 'dark' : 'light');
  applyTheme(theme);

  // Keep in sync with OS changes (only when no manual override)
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
    if (!LS.get('theme')) applyTheme(e.matches ? 'dark' : 'light');
  });

  // Load saved credentials
  const host   = LS.get('host');
  const user   = LS.get('user');
  const model  = LS.get('model')  || 'claude-haiku-4-5-20251001';
  const db     = LS.get('db')     || '';
  // Sensitive – from sessionStorage (empty if tab was closed and reopened)
  const pass   = SS.get('pass')   || '';
  const apiKey = SS.get('apiKey') || '';

  if (!host || !user || !pass) {
    // First run or session expired – show modal, can't be closed
    document.getElementById('modalClose').style.display = 'none';
    openSettings();
    if (host && user && !pass) setStatus('Session expired. Please re-enter your password.', 'info');
    return;
  }

  state = { host, user, pass, apiKey, model, db, databases: [], schema: {} };

  // Reconnect and load DBs
  (async () => {
    const r = await api('test_connection');
    if (!r.ok) {
      document.getElementById('modalClose').style.display = 'none';
      openSettings();
      setStatus('Saved credentials failed: ' + r.error, 'error');
      return;
    }
    state.databases = r.databases;

    if (db && r.databases.includes(db)) {
      document.getElementById('pickerArea').style.display = 'none';
      document.getElementById('workspace').style.display  = 'flex';
      updateDbHeader();
      await loadSchema(db);
      restoreInputs();
    } else {
      showDbPicker();
    }
  })();
})();
</script>
</body>
</html>
