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

/* ── results toolbar ─────────────────────────── */
.results-toolbar{display:flex;align-items:center;gap:8px;padding:7px 14px;border-bottom:1px solid var(--line);background:var(--bg1);flex-shrink:0}
.results-info{font-size:11.5px;color:var(--muted);font-family:monospace;flex:1}
.results-info strong{color:var(--text)}
.btn-sm{display:flex;align-items:center;gap:5px;background:none;border:1px solid var(--line);border-radius:5px;color:var(--muted);font-size:11px;font-weight:500;padding:4px 9px;cursor:pointer;transition:all .15s;white-space:nowrap}
.btn-sm:hover{border-color:var(--accent);color:var(--text)}
.btn-sm svg{flex-shrink:0}
.btn-sm.active{background:rgba(220,38,38,.08);border-color:rgba(220,38,38,.3);color:var(--red)}
[data-theme="dark"] .btn-sm.active{background:rgba(248,113,113,.1)}

/* ── pagination ──────────────────────────────── */
.pagination{display:flex;align-items:center;gap:4px;padding:8px 14px;border-top:1px solid var(--line);background:var(--bg1);flex-shrink:0;justify-content:center}
.pg-btn{background:none;border:1px solid var(--line);border-radius:5px;color:var(--muted);font-size:12px;font-family:monospace;padding:4px 10px;cursor:pointer;transition:all .15s;min-width:32px}
.pg-btn:hover:not(:disabled){border-color:var(--accent);color:var(--text)}
.pg-btn:disabled{opacity:.35;cursor:default}
.pg-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.pg-info{font-size:11.5px;color:var(--muted);font-family:monospace;padding:0 8px}

/* ── history dropdown ────────────────────────── */
.history-wrap{position:relative}
.history-drop{position:absolute;top:calc(100% + 4px);right:0;width:480px;max-width:90vw;background:var(--bg1);border:1px solid var(--line);border-radius:8px;box-shadow:var(--shadow-lg);z-index:200;overflow:hidden;animation:fadeIn .15s}
.history-drop.hidden{display:none}
.history-drop-hdr{display:flex;align-items:center;justify-content:space-between;padding:8px 12px;border-bottom:1px solid var(--line)}
.history-drop-hdr span{font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--dim)}
.history-drop-hdr button{background:none;border:none;font-size:11px;color:var(--dim);cursor:pointer}
.history-drop-hdr button:hover{color:var(--red)}
.history-list{max-height:260px;overflow-y:auto}
.history-item{display:flex;align-items:flex-start;gap:8px;padding:8px 12px;cursor:pointer;border-bottom:1px solid var(--line);transition:background .1s}
.history-item:last-child{border-bottom:none}
.history-item:hover{background:var(--bg2)}
.history-item pre{flex:1;font-family:monospace;font-size:11.5px;color:var(--body);white-space:pre-wrap;word-break:break-all;margin:0;line-height:1.4}
.history-item time{font-size:10px;color:var(--dim);white-space:nowrap;margin-top:1px;flex-shrink:0}
.history-empty{padding:20px;text-align:center;font-size:12px;color:var(--dim);font-family:monospace}

/* ── read-only badge ─────────────────────────── */
.ro-badge{display:none;align-items:center;gap:5px;background:rgba(220,38,38,.08);border:1px solid rgba(220,38,38,.25);border-radius:20px;padding:3px 10px;font-size:11px;color:var(--red);font-weight:600}
[data-theme="dark"] .ro-badge{background:rgba(248,113,113,.1)}
.ro-badge.on{display:flex}

/* ── autocomplete ────────────────────────────── */
.ac-drop{position:absolute;background:var(--bg1);border:1px solid var(--line);border-radius:6px;box-shadow:var(--shadow-lg);z-index:300;min-width:180px;max-width:300px;overflow:hidden;font-family:monospace;font-size:12.5px}
.ac-drop.hidden{display:none}
.ac-item{padding:6px 12px;cursor:pointer;color:var(--body);display:flex;align-items:center;justify-content:space-between;gap:10px;transition:background .1s}
.ac-item:hover,.ac-item.sel{background:var(--accent);color:#fff}
.ac-item:hover .ac-kind,.ac-item.sel .ac-kind{color:rgba(255,255,255,.7)}
.ac-kind{font-size:10px;color:var(--dim)}

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

/* ── row detail modal ────────────────────────── */
#rowOverlay{z-index:1100}
.row-modal{background:var(--bg1);border:1px solid var(--line);border-radius:10px;width:100%;max-width:560px;max-height:86vh;display:flex;flex-direction:column;box-shadow:var(--shadow-lg);animation:slideUp .2s}
.row-modal-hdr{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--line);flex-shrink:0}
.row-modal-hdr h2{font-size:14px;font-weight:700;color:var(--hi);font-family:monospace}
.row-modal-body{overflow-y:auto;padding:16px 20px;display:flex;flex-direction:column;gap:10px}
.row-modal-body::-webkit-scrollbar{width:4px}
.row-modal-body::-webkit-scrollbar-thumb{background:var(--line);border-radius:4px}
.row-field{display:flex;flex-direction:column;gap:3px}
.row-field label{font-size:10px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);display:flex;align-items:center;gap:5px}
.row-field label .pk-badge{background:rgba(217,119,6,.12);border:1px solid rgba(217,119,6,.3);color:var(--amber);border-radius:3px;padding:0 4px;font-size:9px}
.row-field input,.row-field textarea{background:var(--bg0);border:1px solid var(--line);border-radius:6px;color:var(--hi);font-family:monospace;font-size:12.5px;padding:7px 10px;outline:none;transition:border-color .15s;width:100%}
.row-field input:focus,.row-field textarea:focus{border-color:var(--accent)}
.row-field input[readonly],.row-field textarea[readonly]{color:var(--muted);cursor:default;background:var(--bg2)}
.row-field textarea{resize:vertical;min-height:60px;max-height:160px}
.row-null{color:var(--dim);font-style:italic;font-size:12px}
.row-modal-ftr{padding:12px 20px;border-top:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:10px;flex-shrink:0}
.row-modal-ftr .ftr-left{font-size:11px;color:var(--muted);font-family:monospace;min-height:16px}
.row-modal-ftr .ftr-left.ok{color:var(--green)}
.row-modal-ftr .ftr-left.error{color:var(--red)}
.btn-save{display:flex;align-items:center;gap:6px;background:var(--accent);border:none;border-radius:6px;color:#fff;font-size:12px;font-weight:600;padding:7px 16px;cursor:pointer;transition:opacity .15s}
.btn-save:hover{opacity:.88}
.btn-save:disabled{opacity:.5;pointer-events:none}
table.rt tbody tr.clickable-row{cursor:pointer}
table.rt tbody tr.clickable-row:hover td{color:var(--accent)}
table.rt td[data-pk]{cursor:default}
table.rt td[data-pk]:hover{color:inherit!important}
table.rt td.td-editing{background:rgba(37,99,235,.07)!important;outline:2px solid var(--accent);outline-offset:-2px;padding:0!important}
[data-theme="dark"] table.rt td.td-editing{background:rgba(59,130,246,.08)!important}
.inline-edit-input{width:100%;height:100%;border:none;outline:none;background:transparent;color:var(--hi);font-family:monospace;font-size:12px;padding:7px 14px;box-sizing:border-box}

/* ── floating inline save bar ────────────────── */
.inline-save-bar{position:fixed;right:20px;bottom:28px;background:var(--bg1);border:1px solid var(--accent);border-radius:8px;padding:10px 14px;display:flex;align-items:center;gap:10px;box-shadow:var(--shadow-lg);z-index:600;animation:slideUp .15s}
.inline-save-bar.hidden{display:none}
.inline-save-msg{font-size:11.5px;font-family:monospace;color:var(--muted);max-width:220px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.inline-save-msg.ok{color:var(--green)}
.inline-save-msg.error{color:var(--red)}
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

/* ── Prism SQL overlay editor ────────────────── */
.sql-editor-outer{position:relative}
/* shared font metrics – must match textarea exactly */
.sql-highlight,.sql-input{
  font-family:"JetBrains Mono","Fira Code",Consolas,monospace!important;
  font-size:13px!important;line-height:1.65!important;
  padding:12px 14px!important;tab-size:2!important;
  white-space:pre-wrap!important;word-wrap:break-word!important;overflow-wrap:break-word!important;
  letter-spacing:0!important;
}
.sql-highlight{
  position:absolute;top:0;left:0;width:100%;height:100%;
  margin:0!important;border:none!important;border-radius:0!important;
  background:transparent!important;
  pointer-events:none;overflow:hidden!important;
  z-index:0;box-shadow:none!important;
}
/* strip coy decorative shadows */
.sql-highlight:before,.sql-highlight:after{display:none!important}
.sql-highlight>code{
  display:block!important;height:100%!important;
  padding:0!important;border:none!important;box-shadow:none!important;
  background:transparent!important;background-image:none!important;
  font-family:inherit!important;font-size:inherit!important;
  line-height:inherit!important;tab-size:inherit!important;
  white-space:pre-wrap!important;word-wrap:break-word!important;
}
.sql-input{
  position:relative;z-index:1;
  background:transparent!important;
  color:transparent!important;
  caret-color:var(--accent)!important;
  resize:vertical;
}
/* light: prism-coy token colors only (no layout) */
:root:not([data-theme="dark"]) .sql-highlight code .token.comment,.token.block-comment,.token.prolog,.token.doctype,.token.cdata{color:#7d8b99}
:root:not([data-theme="dark"]) .sql-highlight code .token.punctuation{color:#5f6364}
:root:not([data-theme="dark"]) .sql-highlight code .token.boolean,.token.number,.token.tag,.token.constant,.token.symbol,.token.deleted{color:#c92c2c}
:root:not([data-theme="dark"]) .sql-highlight code .token.string,.token.char,.token.attr-name,.token.builtin,.token.inserted,.token.selector{color:#2f9c0a}
:root:not([data-theme="dark"]) .sql-highlight code .token.keyword,.token.atrule,.token.attr-value,.token.class-name{color:#1990b8}
:root:not([data-theme="dark"]) .sql-highlight code .token.operator,.token.entity,.token.url,.token.variable{color:#a67f59}
/* dark: prism-tomorrow token colors */
[data-theme="dark"] .sql-highlight code .token.comment,.token.block-comment,.token.prolog,.token.doctype,.token.cdata{color:#999}
[data-theme="dark"] .sql-highlight code .token.punctuation{color:#ccc}
[data-theme="dark"] .sql-highlight code .token.boolean,.token.number,.token.function{color:#f08d49}
[data-theme="dark"] .sql-highlight code .token.string,.token.char,.token.attr-value,.token.regex,.token.variable{color:#7ec699}
[data-theme="dark"] .sql-highlight code .token.keyword,.token.atrule,.token.builtin,.token.selector{color:#cc99cd}
[data-theme="dark"] .sql-highlight code .token.operator,.token.entity,.token.url{color:#67cdcc}
[data-theme="dark"] .sql-highlight code .token.class-name,.token.constant,.token.property,.token.symbol{color:#f8c555}
[data-theme="dark"] .sql-highlight code .token.tag,.token.deleted{color:#e2777a}

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

  <div class="ro-badge" id="roBadge">
    <svg width="11" height="11" viewBox="0 0 16 16" fill="none"><rect x="3" y="7" width="10" height="8" rx="1.5" stroke="currentColor" stroke-width="1.4"/><path d="M5 7V5a3 3 0 016 0v2" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>
    Read-only
  </div>

  <div class="header-gap"></div>

  <button class="icon-btn" id="roBtn" onclick="toggleReadOnly()" title="Toggle read-only mode">
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><rect x="3" y="7" width="10" height="8" rx="1.5" stroke="currentColor" stroke-width="1.4"/><path d="M5 7V5a3 3 0 016 0v2" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>
    <span>Read-only</span>
  </button>

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
<div class="overlay hidden" id="overlay">
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
      <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding:2px 0">
        <input type="checkbox" id="cfgRemember" style="width:14px;height:14px;accent-color:var(--accent);cursor:pointer">
        <span style="font-size:12px;color:var(--muted)">Remember credentials on this device</span>
      </label>
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

<!-- ── INLINE SAVE BAR ────────────────────────── -->
<div class="inline-save-bar hidden" id="inlineSaveBar">
  <span class="inline-save-msg" id="inlineSaveMsg">Double-click to edit</span>
  <button class="btn-sm" onclick="cancelInlineEdit()">Cancel</button>
  <button class="btn-save" id="btnInlineSave" onclick="commitInlineEdit()">
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M2 9l4 4 8-8" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
    Save
  </button>
</div>

<!-- ── ROW DETAIL MODAL ───────────────────────── -->
<div class="overlay hidden" id="rowOverlay" onclick="if(event.target===this)closeRowModal()">
  <div class="row-modal">
    <div class="row-modal-hdr">
      <h2 id="rowModalTitle">Row</h2>
      <button class="modal-close" onclick="closeRowModal()">✕</button>
    </div>
    <div class="row-modal-body" id="rowModalBody"></div>
    <div class="row-modal-ftr">
      <span class="ftr-left" id="rowModalStatus"></span>
      <div style="display:flex;gap:8px">
        <button class="btn-sm" onclick="closeRowModal()">Close</button>
        <button class="btn-save" id="btnSaveRow" onclick="saveRow()" style="display:none">
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M2 9l4 4 8-8" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
          Save changes
        </button>
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
      <div class="sec-label" style="justify-content:space-between">
        <span style="display:flex;align-items:center;gap:6px">
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M4 5l-2 3 2 3M12 5l2 3-2 3M9 3l-2 10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
          SQL Query
        </span>
        <div class="history-wrap">
          <button class="btn-sm" id="historyBtn" onclick="toggleHistory()" title="Query history">
            <svg width="11" height="11" viewBox="0 0 16 16" fill="none"><path d="M8 3v5l3 3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/><path d="M1.5 8a6.5 6.5 0 101 -3.5L1 3v3h3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
            History
          </button>
          <div class="history-drop hidden" id="historyDrop">
            <div class="history-drop-hdr">
              <span>Recent queries</span>
              <button onclick="clearHistory()">Clear all</button>
            </div>
            <div class="history-list" id="historyList"></div>
          </div>
        </div>
      </div>
      <div style="position:relative">
        <div class="sql-wrap">
          <div class="sql-editor-outer">
            <pre class="language-sql sql-highlight" aria-hidden="true"><code id="sqlHighlightCode"></code></pre>
            <textarea id="sqlInput" class="sql-input"
              placeholder="SELECT * FROM users LIMIT 20;&#10;&#10;-- Ctrl+Enter to run"
              spellcheck="false" autocomplete="off" autocorrect="off"></textarea>
          </div>
        </div>
        <div class="ac-drop hidden" id="acDrop"></div>
      </div>
      <div class="sql-footer">
        <span class="hints"><kbd>Ctrl</kbd>+<kbd>Enter</kbd> to run &nbsp;·&nbsp; <kbd>Ctrl</kbd>+<kbd>Space</kbd> autocomplete</span>
        <button class="btn-run" id="btnRun" onclick="doQuery()">
          <svg width="13" height="13" viewBox="0 0 16 16" fill="none"><path d="M4 2.5l9 5.5-9 5.5V2.5z" fill="currentColor"/></svg>
          Run
        </button>
      </div>
    </div>

    <!-- msg -->
    <div id="msgBar" style="display:none" class="msg-bar"></div>

    <!-- results toolbar -->
    <div class="results-toolbar" id="resultsToolbar" style="display:none">
      <span class="results-info" id="resultsInfo"></span>
      <button class="btn-sm" onclick="exportCsv()">
        <svg width="11" height="11" viewBox="0 0 16 16" fill="none"><path d="M8 2v9M5 8l3 3 3-3M2 13h12" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>
        Export CSV
      </button>
    </div>

    <!-- results -->
    <div class="results" id="resultsArea">
      <div class="empty-state">
        <svg width="40" height="40" viewBox="0 0 40 40" fill="none"><rect x="4" y="4" width="32" height="32" rx="4" stroke="currentColor" stroke-width="1.5"/><path d="M4 14h32M14 14v22M4 24h32" stroke="currentColor" stroke-width="1.2" stroke-dasharray="3 2"/></svg>
        <span>Run a query to see results</span>
      </div>
    </div>

    <!-- pagination -->
    <div class="pagination" id="paginationBar" style="display:none"></div>

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
  document.getElementById('cfgHost').value    = state.host   || LS.get('host')   || '';
  document.getElementById('cfgPort').value    = LS.get('port') || '';
  document.getElementById('cfgUser').value    = state.user   || LS.get('user')   || '';
  document.getElementById('cfgPass').value    = state.pass   || LS.get('pass')   || SS.get('pass')   || '';
  document.getElementById('cfgApiKey').value  = state.apiKey || LS.get('apiKey') || SS.get('apiKey') || '';
  document.getElementById('cfgModel').value   = state.model  || LS.get('model')  || 'claude-haiku-4-5-20251001';
  document.getElementById('cfgRemember').checked = LS.get('remember') === '1';
  setStatus('Enter your MySQL credentials above.', 'info');
  document.getElementById('overlay').classList.remove('hidden');
  document.getElementById('modalClose').style.display = state.host ? '' : 'none';
}

function closeSettings() {
  if (!state.host) return; // can't close without saving first
  document.getElementById('overlay').classList.add('hidden');
}

async function saveAndConnect() {
  const host   = (document.getElementById('cfgHost').value.trim() || 'localhost')
               + ':' + (document.getElementById('cfgPort').value.trim() || '3306');
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

  const remember = document.getElementById('cfgRemember').checked;
  LS.set('remember', remember ? '1' : '0');
  // Always save non-sensitive to localStorage
  LS.set('host',  host);
  LS.set('user',  user);
  LS.set('model', model);
  // Sensitive: localStorage if "remember" checked, sessionStorage only otherwise
  if (remember) {
    LS.set('pass', pass); LS.set('apiKey', apiKey);
    SS.del('pass'); SS.del('apiKey');
  } else {
    SS.set('pass', pass); SS.set('apiKey', apiKey);
    LS.del('pass'); LS.del('apiKey');
  }

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

// ── Read-only mode ────────────────────────────
let readOnly = LS.get('readOnly') === '1';
function toggleReadOnly() {
  readOnly = !readOnly;
  LS.set('readOnly', readOnly ? '1' : '0');
  updateRoUi();
}
function updateRoUi() {
  document.getElementById('roBadge').classList.toggle('on', readOnly);
  document.getElementById('roBtn').classList.toggle('active', readOnly);
}

// ── Query ─────────────────────────────────────
async function doQuery() {
  const sql = document.getElementById('sqlInput').value.trim();
  if (!sql) return;

  if (readOnly) {
    const first = sql.replace(/\/\*.*?\*\//gs, '').replace(/--[^\n]*/g, '').trim().toUpperCase();
    if (!/^SELECT\b/.test(first)) {
      showMsg('Read-only mode: only SELECT queries are allowed.', 'error');
      return;
    }
  }

  setBtn('btnRun', true, '<span class="spin"></span> Running…');
  hideMsg();
  const t0 = Date.now();
  const r = await api('query', { sql });
  const ms = Date.now() - t0;
  setBtn('btnRun', false, '<svg width="13" height="13" viewBox="0 0 16 16" fill="none"><path d="M4 2.5l9 5.5-9 5.5V2.5z" fill="currentColor"/></svg> Run');

  if (!r.ok) { showMsg(r.error, 'error'); clearResults(); return; }

  saveHistory(sql);

  if (r.type === 'write') {
    showMsg(`Query OK – ${r.affected} row(s) affected. (${ms}ms)`, 'ok');
    clearResults();
  } else {
    showMsg(`${r.rows.length} row(s) returned in ${ms}ms.`, 'ok');
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
  syncHighlight();
  if (r.explanation) {
    document.getElementById('aiExplainText').textContent = r.explanation;
    document.getElementById('aiExplain').style.display = 'flex';
  }
  hideMsg();
}

// ── Render table ──────────────────────────────
const PAGE_SIZE = 50;
let sortState = { col: null, dir: 1 };
let lastCols = [], lastRows = [], lastSorted = [];
let currentPage = 0;

function renderTable(cols, rows, sortCol = null, sortDir = 1, page = 0) {
  lastCols = cols; lastRows = rows;
  sortState = { col: sortCol, dir: sortDir };
  currentPage = page;

  lastSorted = sortCol === null ? rows : [...rows].sort((a, b) => {
    const av = a[sortCol] ?? '', bv = b[sortCol] ?? '';
    const an = parseFloat(av), bn = parseFloat(bv);
    const cmp = (!isNaN(an) && !isNaN(bn)) ? an - bn : String(av).localeCompare(String(bv));
    return cmp * sortDir;
  });

  const totalPages = Math.ceil(lastSorted.length / PAGE_SIZE);
  const pageRows   = lastSorted.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const th = cols.map((c, i) => {
    const active = i === sortCol;
    const arrow  = active ? (sortDir === 1 ? ' ↑' : ' ↓') : '';
    return `<th class="sortable${active ? ' sort-active' : ''}" onclick="sortBy(${i})">${escH(c)}${arrow}</th>`;
  }).join('');

  const tb = pageRows.map((row, ri) => {
    const absIdx = page * PAGE_SIZE + ri;
    const tds = row.map((v, ci) => {
      const content = v === null ? '<span class="null-v">NULL</span>' : escH(String(v));
      return `<td data-col-idx="${ci}">${content}</td>`;
    }).join('');
    return `<tr class="clickable-row" data-abs-idx="${absIdx}">${tds}</tr>`;
  }).join('');

  document.getElementById('resultsArea').innerHTML =
    `<div class="result-wrap"><table class="rt"><thead><tr>${th}</tr></thead><tbody>${tb}</tbody></table></div>`;

  attachRowListeners();

  // toolbar
  const toolbar = document.getElementById('resultsToolbar');
  toolbar.style.display = 'flex';
  const start = page * PAGE_SIZE + 1, end = Math.min((page + 1) * PAGE_SIZE, lastSorted.length);
  document.getElementById('resultsInfo').innerHTML =
    `<strong>${lastSorted.length}</strong> row${lastSorted.length !== 1 ? 's' : ''}` +
    (totalPages > 1 ? ` &nbsp;·&nbsp; showing <strong>${start}–${end}</strong>` : '');

  // pagination
  const pgBar = document.getElementById('paginationBar');
  if (totalPages <= 1) { pgBar.style.display = 'none'; return; }
  pgBar.style.display = 'flex';

  const maxBtns = 7;
  let pages = [];
  if (totalPages <= maxBtns) {
    pages = Array.from({length: totalPages}, (_, i) => i);
  } else {
    pages = [0];
    let lo = Math.max(1, page - 2), hi = Math.min(totalPages - 2, page + 2);
    if (lo > 1) pages.push('…');
    for (let i = lo; i <= hi; i++) pages.push(i);
    if (hi < totalPages - 2) pages.push('…');
    pages.push(totalPages - 1);
  }

  pgBar.innerHTML =
    `<button class="pg-btn" onclick="goPage(${page - 1})" ${page === 0 ? 'disabled' : ''}>‹</button>` +
    pages.map(p => p === '…'
      ? `<span class="pg-info">…</span>`
      : `<button class="pg-btn${p === page ? ' active' : ''}" onclick="goPage(${p})">${p + 1}</button>`
    ).join('') +
    `<button class="pg-btn" onclick="goPage(${page + 1})" ${page >= totalPages - 1 ? 'disabled' : ''}>›</button>`;
}

function sortBy(col) {
  const dir = sortState.col === col ? -sortState.dir : 1;
  renderTable(lastCols, lastRows, col, dir, 0);
}

function goPage(p) {
  const totalPages = Math.ceil(lastSorted.length / PAGE_SIZE);
  if (p < 0 || p >= totalPages) return;
  renderTable(lastCols, lastRows, sortState.col, sortState.dir, p);
  document.getElementById('resultsArea').scrollTop = 0;
}

// ── CSV export ────────────────────────────────
function exportCsv() {
  if (!lastCols.length) return;
  const escape = v => '"' + String(v === null ? '' : v).replace(/"/g, '""') + '"';
  const lines = [lastCols.map(escape).join(',')];
  lastSorted.forEach(row => lines.push(row.map(escape).join(',')));
  const blob = new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
  const url  = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), { href: url, download: (state.db || 'results') + '.csv' });
  a.click();
  URL.revokeObjectURL(url);
}

function clearResults() {
  lastCols = []; lastRows = []; lastSorted = [];
  document.getElementById('resultsArea').innerHTML =
    `<div class="empty-state">
      <svg width="40" height="40" viewBox="0 0 40 40" fill="none"><rect x="4" y="4" width="32" height="32" rx="4" stroke="currentColor" stroke-width="1.5"/><path d="M4 14h32M14 14v22M4 24h32" stroke="currentColor" stroke-width="1.2" stroke-dasharray="3 2"/></svg>
      <span>Run a query to see results</span>
    </div>`;
  document.getElementById('resultsToolbar').style.display = 'none';
  document.getElementById('paginationBar').style.display  = 'none';
}

// ── Row detail / edit modal ───────────────────
let rowModalData = { cols: [], row: [], tableName: '', pkCols: [] };

function detectTableFromSql(sql) {
  const m = sql.replace(/\/\*.*?\*\//gs,'').replace(/--[^\n]*/g,'')
               .match(/\bFROM\s+`?(\w+)`?/i);
  return m ? m[1] : null;
}

function openRowModal(absIdx) {
  const row  = lastSorted[absIdx];
  const cols = lastCols;
  if (!row || !cols.length) return;

  // Try to detect which table the query hit
  const sql  = document.getElementById('sqlInput').value.trim();
  const tbl  = detectTableFromSql(sql);
  const schemaCols = (tbl && state.schema[tbl]) ? state.schema[tbl] : [];
  const pkCols = schemaCols.filter(c => c.COLUMN_KEY === 'PRI').map(c => c.COLUMN_NAME);

  rowModalData = { cols, row, tableName: tbl, pkCols };

  document.getElementById('rowModalTitle').textContent = tbl ? tbl + ' — row detail' : 'Row detail';

  const body = document.getElementById('rowModalBody');
  body.innerHTML = cols.map((col, i) => {
    const val  = row[i];
    const sc   = schemaCols.find(c => c.COLUMN_NAME === col);
    const isPk = pkCols.includes(col);
    const isLong = sc && /text|blob|json/i.test(sc.COLUMN_TYPE);
    const pkBadge = isPk ? '<span class="pk-badge">PK</span>' : '';
    const label = `<label>${escH(col)}${pkBadge}${sc ? `<span style="color:var(--dim);font-weight:400;text-transform:none;margin-left:4px">${escH(sc.COLUMN_TYPE)}</span>` : ''}</label>`;
    const safeVal = val === null ? '' : String(val);
    const field = isLong
      ? `<textarea data-col="${escH(col)}" data-idx="${i}"${isPk ? ' readonly' : ''}>${escH(safeVal)}</textarea>`
      : `<input type="text" data-col="${escH(col)}" data-idx="${i}"${isPk ? ' readonly' : ''} value="${escH(safeVal)}">`;
    return `<div class="row-field">${label}${field}</div>`;
  }).join('');

  // Show Save button only if we know the table and it has a PK
  const canSave = tbl && pkCols.length > 0 && !readOnly;
  document.getElementById('btnSaveRow').style.display = canSave ? '' : 'none';
  document.getElementById('rowModalStatus').textContent =
    !tbl ? 'Read-only: table not detected (complex query).' :
    !pkCols.length ? 'Read-only: no primary key found.' :
    readOnly ? 'Read-only mode is on.' : '';
  document.getElementById('rowModalStatus').className = 'ftr-left';

  document.getElementById('rowOverlay').classList.remove('hidden');
}

function closeRowModal() {
  document.getElementById('rowOverlay').classList.add('hidden');
  document.getElementById('rowModalStatus').textContent = '';
}

async function saveRow() {
  const { cols, row, tableName, pkCols } = rowModalData;
  if (!tableName || !pkCols.length) return;

  const inputs = document.getElementById('rowModalBody').querySelectorAll('[data-col]');
  const setClauses = [], setVals = [];
  const whereClauses = [], whereVals = [];

  inputs.forEach(el => {
    const col = el.getAttribute('data-col');
    const idx = parseInt(el.getAttribute('data-idx'));
    const newVal = el.value;
    const origVal = row[idx];

    if (pkCols.includes(col)) {
      whereClauses.push('`' + col + '` = ?');
      whereVals.push(origVal === null ? 'NULL' : origVal);
    } else {
      setClauses.push('`' + col + '` = ?');
      setVals.push(newVal === '' && origVal === null ? '__NULL__' : newVal);
    }
  });

  if (!setClauses.length) {
    rowModalStatus('Nothing to update (all editable fields unchanged).', 'error');
    return;
  }

  // Build parameterised-style SQL (server side uses real_escape_string)
  const allVals = [...setVals, ...whereVals];
  let sql = `UPDATE \`${tableName}\` SET ${setClauses.join(', ')} WHERE ${whereClauses.join(' AND ')}`;

  // Substitute placeholders with escaped values (JS side — server validates too)
  let i = 0;
  const sqlFinal = sql.replace(/\?/g, () => {
    const v = allVals[i++];
    if (v === '__NULL__') return 'NULL';
    return "'" + v.replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'";
  });

  const btn = document.getElementById('btnSaveRow');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Saving…';

  const r = await api('query', { sql: sqlFinal });

  btn.disabled = false;
  btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M2 9l4 4 8-8" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg> Save changes';

  if (!r.ok) {
    rowModalStatus(r.error, 'error');
  } else {
    rowModalStatus(`Saved — ${r.affected} row(s) affected.`, 'ok');
    // Update local lastSorted so the table reflects changes without re-query
    const body = document.getElementById('rowModalBody');
    body.querySelectorAll('[data-col]').forEach(el => {
      const idx = parseInt(el.getAttribute('data-idx'));
      lastSorted.forEach(sr => { if (sr === rowModalData.row) sr[idx] = el.value; });
    });
  }
}

function rowModalStatus(msg, cls) {
  const el = document.getElementById('rowModalStatus');
  el.textContent = msg;
  el.className = 'ftr-left ' + cls;
}

// ── Inline edit ───────────────────────────────
let activeInlineEdit = null;
let inlineClickTimer = null;

function attachRowListeners() {
  const sql = document.getElementById('sqlInput').value.trim();
  const tbl = detectTableFromSql(sql);
  const schemaCols = (tbl && state.schema[tbl]) ? state.schema[tbl] : [];
  const pkSet = new Set(schemaCols.filter(c => c.COLUMN_KEY === 'PRI').map(c => c.COLUMN_NAME));

  document.querySelectorAll('table.rt tbody tr.clickable-row').forEach(tr => {
    const absIdx = parseInt(tr.dataset.absIdx);

    // Single-click: open modal (delayed so double-click can cancel it)
    tr.addEventListener('click', e => {
      if (activeInlineEdit) return;
      if (e.detail >= 2) return; // part of a double-click
      clearTimeout(inlineClickTimer);
      inlineClickTimer = setTimeout(() => openRowModal(absIdx), 220);
    });

    // Double-click on a cell: inline edit
    tr.querySelectorAll('td').forEach((td, colIdx) => {
      const colName = lastCols[colIdx];
      if (pkSet.has(colName)) {
        td.dataset.pk = '1';
        td.title = 'Primary key — not editable';
        return;
      }
      td.addEventListener('dblclick', e => {
        clearTimeout(inlineClickTimer);
        startInlineEdit(td, absIdx, colIdx, tbl, pkSet);
      });
    });
  });
}

function startInlineEdit(td, absIdx, colIdx, tbl, pkSet) {
  if (activeInlineEdit) cancelInlineEdit();
  if (readOnly) { setInlineSaveMsg('Read-only mode is on.', 'error'); showInlineSaveBar(); return; }
  if (!tbl)    { setInlineSaveMsg('Table not detected — complex query.', 'error'); showInlineSaveBar(); return; }
  if (!pkSet.size) { setInlineSaveMsg('No primary key found.', 'error'); showInlineSaveBar(); return; }

  const origVal = lastSorted[absIdx][colIdx];
  const input = document.createElement('input');
  input.className = 'inline-edit-input';
  input.value = origVal === null ? '' : String(origVal);
  td.classList.add('td-editing');
  td.innerHTML = '';
  td.appendChild(input);
  input.focus();
  input.select();

  activeInlineEdit = { td, absIdx, colIdx, origVal, tbl, pkSet, input };
  setInlineSaveMsg(`Editing ${lastCols[colIdx]}…`, '');
  showInlineSaveBar();

  input.addEventListener('keydown', e => {
    if (e.key === 'Enter')  { e.preventDefault(); commitInlineEdit(); }
    if (e.key === 'Escape') { cancelInlineEdit(); }
  });
}

function cancelInlineEdit() {
  if (!activeInlineEdit) return;
  const { td, origVal } = activeInlineEdit;
  td.classList.remove('td-editing');
  td.innerHTML = origVal === null ? '<span class="null-v">NULL</span>' : escH(String(origVal));
  activeInlineEdit = null;
  hideInlineSaveBar();
}

async function commitInlineEdit() {
  if (!activeInlineEdit) return;
  const { td, absIdx, colIdx, origVal, tbl, pkSet, input } = activeInlineEdit;
  const newVal = input.value;
  if (newVal === String(origVal === null ? '' : origVal)) { cancelInlineEdit(); return; }

  const row = lastSorted[absIdx];
  const whereParts = [], whereVals = [];
  lastCols.forEach((col, i) => {
    if (pkSet.has(col)) {
      whereParts.push('`' + col + '` = \'' + String(row[i]).replace(/\\/g,'\\\\').replace(/'/g,"\\'") + '\'');
    }
  });
  if (!whereParts.length) { setInlineSaveMsg('No PK values in result set.', 'error'); return; }

  const setClause = '`' + lastCols[colIdx] + '` = \'' + newVal.replace(/\\/g,'\\\\').replace(/'/g,"\\'") + '\'';
  const sql = `UPDATE \`${tbl}\` SET ${setClause} WHERE ${whereParts.join(' AND ')}`;

  const btn = document.getElementById('btnInlineSave');
  btn.disabled = true;
  setInlineSaveMsg('Saving…', '');

  const r = await api('query', { sql });
  btn.disabled = false;

  if (!r.ok) {
    setInlineSaveMsg(r.error, 'error');
    return;
  }

  // Update local data and restore cell
  row[colIdx] = newVal;
  td.classList.remove('td-editing');
  td.innerHTML = escH(newVal);
  activeInlineEdit = null;
  setInlineSaveMsg(`Saved — ${r.affected} row(s) affected.`, 'ok');
  setTimeout(hideInlineSaveBar, 2000);
}

function showInlineSaveBar() { document.getElementById('inlineSaveBar').classList.remove('hidden'); }
function hideInlineSaveBar() { document.getElementById('inlineSaveBar').classList.add('hidden'); }
function setInlineSaveMsg(msg, cls) {
  const el = document.getElementById('inlineSaveMsg');
  el.textContent = msg;
  el.className = 'inline-save-msg' + (cls ? ' ' + cls : '');
}

// Cancel inline edit when clicking outside the table
document.addEventListener('click', e => {
  if (activeInlineEdit && !e.target.closest('table.rt')) cancelInlineEdit();
});

// ── Query history ─────────────────────────────
function saveHistory(sql) {
  const h = JSON.parse(SS.get('queryHistory') || '[]').filter(x => x.sql !== sql);
  h.unshift({ sql, ts: Date.now() });
  SS.set('queryHistory', JSON.stringify(h.slice(0, 50)));
}

function toggleHistory() {
  const drop = document.getElementById('historyDrop');
  const hidden = drop.classList.toggle('hidden');
  if (!hidden) renderHistory();
}

function renderHistory() {
  const list = document.getElementById('historyList');
  const h = JSON.parse(SS.get('queryHistory') || '[]');
  if (!h.length) { list.innerHTML = '<div class="history-empty">No history yet</div>'; return; }
  list.innerHTML = h.map((item, i) => {
    const ago = formatAgo(item.ts);
    return `<div class="history-item" onclick="useHistory(${i})">
      <pre>${escH(item.sql.length > 120 ? item.sql.slice(0, 120) + '…' : item.sql)}</pre>
      <time>${ago}</time>
    </div>`;
  }).join('');
}

function useHistory(i) {
  const h = JSON.parse(SS.get('queryHistory') || '[]');
  if (h[i]) {
    document.getElementById('sqlInput').value = h[i].sql;
    SS.set('lastSql', h[i].sql);
    syncHighlight();
  }
  document.getElementById('historyDrop').classList.add('hidden');
}

function clearHistory() {
  SS.del('queryHistory');
  renderHistory();
}

function formatAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60)  return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

// Close history when clicking outside
document.addEventListener('click', e => {
  if (!e.target.closest('.history-wrap'))
    document.getElementById('historyDrop')?.classList.add('hidden');
});

// ── Autocomplete ──────────────────────────────
let acItems = [], acIndex = -1;

function buildAcList() {
  const items = [];
  Object.keys(state.schema).forEach(tbl => {
    items.push({ text: tbl, kind: 'table' });
    state.schema[tbl].forEach(c => items.push({ text: c.COLUMN_NAME, kind: tbl }));
  });
  return items;
}

function showAc(filter) {
  const drop = document.getElementById('acDrop');
  const all  = buildAcList();
  const f    = filter.toLowerCase();
  const matches = all.filter(x => x.text.toLowerCase().startsWith(f) && x.text.toLowerCase() !== f).slice(0, 10);
  if (!matches.length) { drop.classList.add('hidden'); return; }

  acItems = matches; acIndex = -1;
  drop.className = 'ac-drop';
  drop.innerHTML = matches.map((m, i) =>
    `<div class="ac-item" data-i="${i}" onmousedown="pickAc(${i})">${escH(m.text)}<span class="ac-kind">${escH(m.kind)}</span></div>`
  ).join('');

  // Position below textarea
  const ta = document.getElementById('sqlInput');
  const rect = ta.getBoundingClientRect();
  const parent = ta.closest('div[style]') || ta.parentElement;
  drop.style.top  = (ta.offsetTop + ta.offsetHeight + 2) + 'px';
  drop.style.left = '12px';
}

function hideAc() {
  document.getElementById('acDrop').classList.add('hidden');
  acItems = []; acIndex = -1;
}

function pickAc(i) {
  const item = acItems[i];
  if (!item) return;
  const ta   = document.getElementById('sqlInput');
  const pos  = ta.selectionStart;
  const text = ta.value;
  // Find start of current word
  let start = pos;
  while (start > 0 && /\w/.test(text[start - 1])) start--;
  ta.value = text.slice(0, start) + item.text + text.slice(pos);
  ta.selectionStart = ta.selectionEnd = start + item.text.length;
  hideAc();
  ta.focus();
}

function updateAcSelection() {
  document.querySelectorAll('#acDrop .ac-item').forEach((el, i) => {
    el.classList.toggle('sel', i === acIndex);
  });
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
  // Autocomplete trigger
  const pos  = e.target.selectionStart;
  const text = e.target.value.slice(0, pos);
  const word = text.match(/\w+$/)?.[0] || '';
  word.length >= 2 ? showAc(word) : hideAc();
});
document.getElementById('aiInput').addEventListener('input', e => {
  SS.set('lastPrompt', e.target.value);
});

function restoreInputs() {
  const sql    = SS.get('lastSql');
  const prompt = SS.get('lastPrompt');
  if (sql)    { document.getElementById('sqlInput').value = sql; syncHighlight(); }
  if (prompt) document.getElementById('aiInput').value  = prompt;
}

// ── Keyboard shortcuts ────────────────────────
document.getElementById('sqlInput').addEventListener('keydown', e => {
  // Autocomplete navigation
  if (!document.getElementById('acDrop').classList.contains('hidden')) {
    if (e.key === 'ArrowDown') { e.preventDefault(); acIndex = Math.min(acIndex + 1, acItems.length - 1); updateAcSelection(); return; }
    if (e.key === 'ArrowUp')   { e.preventDefault(); acIndex = Math.max(acIndex - 1, 0); updateAcSelection(); return; }
    if ((e.key === 'Enter' || e.key === 'Tab') && acIndex >= 0) { e.preventDefault(); pickAc(acIndex); return; }
    if (e.key === 'Escape')    { hideAc(); return; }
  }
  if ((e.ctrlKey || e.metaKey) && e.key === ' ') {
    e.preventDefault();
    const pos = e.target.selectionStart, text = e.target.value.slice(0, pos);
    const word = text.match(/\w+$/)?.[0] || '';
    word.length >= 1 ? showAc(word) : showAc('');
  }
});

document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    if (document.activeElement === document.getElementById('aiInput')) doAsk();
    else doQuery();
  }
  if (e.key === 'Escape') { closeSettings(); hideAc(); }
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
  // Read-only mode
  updateRoUi();

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
  // Sensitive – localStorage if "remember" was checked, otherwise sessionStorage
  const pass   = LS.get('pass')   || SS.get('pass')   || '';
  const apiKey = LS.get('apiKey') || SS.get('apiKey') || '';

  if (!host || !user || !pass) {
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

// ── Prism.js core + SQL (embedded, no CDN) ────
var _self="undefined"!=typeof window?window:"undefined"!=typeof WorkerGlobalScope&&self instanceof WorkerGlobalScope?self:{},Prism=function(l){var n=/(?:^|\s)lang(?:uage)?-([\w-]+)(?=\s|$)/i,t=0,e={},j={manual:l.Prism&&l.Prism.manual,disableWorkerMessageHandler:l.Prism&&l.Prism.disableWorkerMessageHandler,util:{encode:function e(t){return t instanceof C?new C(t.type,e(t.content),t.alias):Array.isArray(t)?t.map(e):t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/\u00a0/g," ")},type:function(e){return Object.prototype.toString.call(e).slice(8,-1)},objId:function(e){return e.__id||Object.defineProperty(e,"__id",{value:++t}),e.__id},clone:function n(e,a){var r,t;switch(a=a||{},j.util.type(e)){case"Object":if(t=j.util.objId(e),a[t])return a[t];for(var s in r={},a[t]=r,e)e.hasOwnProperty(s)&&(r[s]=n(e[s],a));return r;case"Array":return(t=j.util.objId(e),a[t])?a[t]:(r=[],a[t]=r,e.forEach(function(e,t){r[t]=n(e,a)}),r);default:return e}},getLanguage:function(e){for(;e;){var t=n.exec(e.className);if(t)return t[1].toLowerCase();e=e.parentElement}return"none"},setLanguage:function(e,t){e.className=e.className.replace(RegExp(n,"gi"),""),e.classList.add("language-"+t)},currentScript:function(){if("undefined"==typeof document)return null;if("currentScript"in document)return document.currentScript;try{throw new Error}catch(e){var t=(/at [^(\r\n]*\((.*):[^:]+:[^:]+\)$/i.exec(e.stack)||[])[1];if(t){var n,a=document.getElementsByTagName("script");for(n in a)if(a[n].src==t)return a[n]}return null}},isActive:function(e,t,n){for(var a="no-"+t;e;){var r=e.classList;if(r.contains(t))return!0;if(r.contains(a))return!1;e=e.parentElement}return!!n}},languages:{plain:e,plaintext:e,text:e,txt:e,extend:function(e,t){var n,a=j.util.clone(j.languages[e]);for(n in t)a[n]=t[n];return a},insertBefore:function(n,e,t,a){var r,s=(a=a||j.languages)[n],i={};for(r in s)if(s.hasOwnProperty(r)){if(r==e)for(var o in t)t.hasOwnProperty(o)&&(i[o]=t[o]);t.hasOwnProperty(r)||(i[r]=s[r])}var l=a[n];return a[n]=i,j.languages.DFS(j.languages,function(e,t){t===l&&e!=n&&(this[e]=i)}),i},DFS:function e(t,n,a,r){r=r||{};var s,i,o,l=j.util.objId;for(s in t)t.hasOwnProperty(s)&&(n.call(t,s,t[s],a||s),i=t[s],"Object"!==(o=j.util.type(i))||r[l(i)]?"Array"!==o||r[l(i)]||(r[l(i)]=!0,e(i,n,s,r)):(r[l(i)]=!0,e(i,n,null,r)))}},plugins:{},highlightAll:function(e,t){j.highlightAllUnder(document,e,t)},highlightAllUnder:function(e,t,n){var a={callback:n,container:e,selector:'code[class*="language-"], [class*="language-"] code, code[class*="lang-"], [class*="lang-"] code'};j.hooks.run("before-highlightall",a),a.elements=Array.prototype.slice.apply(a.container.querySelectorAll(a.selector)),j.hooks.run("before-all-elements-highlight",a);for(var r,s=0;r=a.elements[s++];)j.highlightElement(r,!0===t,a.callback)},highlightElement:function(e,t,n){var a=j.util.getLanguage(e),r=j.languages[a],s=(j.util.setLanguage(e,a),e.parentElement);s&&"pre"===s.nodeName.toLowerCase()&&j.util.setLanguage(s,a);var i={element:e,language:a,grammar:r,code:e.textContent};function o(e){i.highlightedCode=e,j.hooks.run("before-insert",i),i.element.innerHTML=i.highlightedCode,j.hooks.run("after-highlight",i),j.hooks.run("complete",i),n&&n.call(i.element)}if(j.hooks.run("before-sanity-check",i),(s=i.element.parentElement)&&"pre"===s.nodeName.toLowerCase()&&!s.hasAttribute("tabindex")&&s.setAttribute("tabindex","0"),!i.code)return j.hooks.run("complete",i),void(n&&n.call(i.element));j.hooks.run("before-highlight",i),i.grammar?t&&l.Worker?((a=new Worker(j.filename)).onmessage=function(e){o(e.data)},a.postMessage(JSON.stringify({language:i.language,code:i.code,immediateClose:!0}))):o(j.highlight(i.code,i.grammar,i.language)):o(j.util.encode(i.code))},highlight:function(e,t,n){e={code:e,grammar:t,language:n};if(j.hooks.run("before-tokenize",e),e.grammar)return e.tokens=j.tokenize(e.code,e.grammar),j.hooks.run("after-tokenize",e),C.stringify(j.util.encode(e.tokens),e.language);throw new Error('The language "'+e.language+'" has no grammar.')},tokenize:function(e,t){var n=t.rest;if(n){for(var a in n)t[a]=n[a];delete t.rest}for(var r=new u,s=(z(r,r.head,e),!function e(t,n,a,r,s,i){for(var o in a)if(a.hasOwnProperty(o)&&a[o]){var l=a[o];l=Array.isArray(l)?l:[l];for(var u=0;u<l.length;++u){if(i&&i.cause==o+","+u)return;for(var g,c=l[u],d=c.inside,p=!!c.lookbehind,m=!!c.greedy,h=c.alias,f=(m&&!c.pattern.global&&(g=c.pattern.toString().match(/[imsuy]*$/)[0],c.pattern=RegExp(c.pattern.source,g+"g")),c.pattern||c),b=r.next,y=s;b!==n.tail&&!(i&&y>=i.reach);y+=b.value.length,b=b.next){var v=b.value;if(n.length>t.length)return;if(!(v instanceof C)){var F,x=1;if(m){if(!(F=L(f,y,t,p))||F.index>=t.length)break;var k=F.index,w=F.index+F[0].length,A=y;for(A+=b.value.length;A<=k;)b=b.next,A+=b.value.length;if(A-=b.value.length,y=A,b.value instanceof C)continue;for(var P=b;P!==n.tail&&(A<w||"string"==typeof P.value);P=P.next)x++,A+=P.value.length;x--,v=t.slice(y,A),F.index-=y}else if(!(F=L(f,0,v,p)))continue;var k=F.index,$=F[0],S=v.slice(0,k),E=v.slice(k+$.length),v=y+v.length,_=(i&&v>i.reach&&(i.reach=v),b.prev),S=(S&&(_=z(n,_,S),y+=S.length),O(n,_,x),new C(o,d?j.tokenize($,d):$,h,$));b=z(n,_,S),E&&z(n,b,E),1<x&&($={cause:o+","+u,reach:v},e(t,n,a,b.prev,y,$),i&&$.reach>i.reach&&(i.reach=$.reach))}}}}}(e,r,t,r.head,0),r),i=[],o=s.head.next;o!==s.tail;)i.push(o.value),o=o.next;return i},hooks:{all:{},add:function(e,t){var n=j.hooks.all;n[e]=n[e]||[],n[e].push(t)},run:function(e,t){var n=j.hooks.all[e];if(n&&n.length)for(var a,r=0;a=n[r++];)a(t)}},Token:C};function C(e,t,n,a){this.type=e,this.content=t,this.alias=n,this.length=0|(a||"").length}function L(e,t,n,a){e.lastIndex=t;t=e.exec(n);return t&&a&&t[1]&&(e=t[1].length,t.index+=e,t[0]=t[0].slice(e)),t}function u(){var e={value:null,prev:null,next:null},t={value:null,prev:e,next:null};e.next=t,this.head=e,this.tail=t,this.length=0}function z(e,t,n){var a=t.next,n={value:n,prev:t,next:a};return t.next=n,a.prev=n,e.length++,n}function O(e,t,n){for(var a=t.next,r=0;r<n&&a!==e.tail;r++)a=a.next;(t.next=a).prev=t,e.length-=r}if(l.Prism=j,C.stringify=function t(e,n){if("string"==typeof e)return e;var a;if(Array.isArray(e))return a="",e.forEach(function(e){a+=t(e,n)}),a;var r,s={type:e.type,content:t(e.content,n),tag:"span",classes:["token",e.type],attributes:{},language:n},e=e.alias,i=(e&&(Array.isArray(e)?Array.prototype.push.apply(s.classes,e):s.classes.push(e)),j.hooks.run("wrap",s),"");for(r in s.attributes)i+=" "+r+'="'+(s.attributes[r]||"").replace(/"/g,"&quot;")+'"';return"<"+s.tag+' class="'+s.classes.join(" ")+'"'+i+">"+s.content+"</"+s.tag+">"},!l.document)return l.addEventListener&&(j.disableWorkerMessageHandler||l.addEventListener("message",function(e){var e=JSON.parse(e.data),t=e.language,n=e.code,e=e.immediateClose;l.postMessage(j.highlight(n,j.languages[t],t)),e&&l.close()},!1)),j;var a,e=j.util.currentScript();function r(){j.manual||j.highlightAll()}return e&&(j.filename=e.src,e.hasAttribute("data-manual")&&(j.manual=!0)),j.manual||("loading"===(a=document.readyState)||"interactive"===a&&e&&e.defer?document.addEventListener("DOMContentLoaded",r):window.requestAnimationFrame?window.requestAnimationFrame(r):window.setTimeout(r,16)),j}(_self);"undefined"!=typeof module&&module.exports&&(module.exports=Prism),"undefined"!=typeof global&&(global.Prism=Prism),Prism.languages.markup={comment:{pattern:/<!--(?:(?!<!--)[\s\S])*?-->/,greedy:!0},prolog:{pattern:/<\?[\s\S]+?\?>/,greedy:!0},doctype:{pattern:/<!DOCTYPE(?:[^>"'[\]]|"[^"]*"|'[^']*')+(?:\[(?:[^<"'\]]|"[^"]*"|'[^']*'|<(?!!--)|<!--(?:[^-]|-(?!->))*-->)*\]\s*)?>/i,greedy:!0,inside:{"internal-subset":{pattern:/(^[^\[]*\[)[\s\S]+(?=\]>$)/,lookbehind:!0,greedy:!0,inside:null},string:{pattern:/"[^"]*"|'[^']*'/,greedy:!0},punctuation:/^<!|>$|[[\]]/,"doctype-tag":/^DOCTYPE/i,name:/[^\s<>'"]+/}},cdata:{pattern:/<!\[CDATA\[[\s\S]*?\]\]>/i,greedy:!0},tag:{pattern:/<\/?(?!\d)[^\s>\/=$<%]+(?:\s(?:\s*[^\s>\/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s'">=]+(?=[\s>]))|(?=[\s/>])))+)?\s*\/?>/,greedy:!0,inside:{tag:{pattern:/^<\/?[^\s>\/]+/,inside:{punctuation:/^<\/?/,namespace:/^[^\s>\/:]+:/}},"special-attr":[],"attr-value":{pattern:/=\s*(?:"[^"]*"|'[^']*'|[^\s'">=]+)/,inside:{punctuation:[{pattern:/^=/,alias:"attr-equals"},{pattern:/^(\s*)["']|["']$/,lookbehind:!0}]}},punctuation:/\/?>/,"attr-name":{pattern:/[^\s>\/]+/,inside:{namespace:/^[^\s>\/:]+:/}}}},entity:[{pattern:/&[\da-z]{1,8};/i,alias:"named-entity"},/&#x?[\da-f]{1,8};/i]},Prism.languages.markup.tag.inside["attr-value"].inside.entity=Prism.languages.markup.entity,Prism.languages.markup.doctype.inside["internal-subset"].inside=Prism.languages.markup,Prism.hooks.add("wrap",function(e){"entity"===e.type&&(e.attributes.title=e.content.replace(/&amp;/,"&"))}),Object.defineProperty(Prism.languages.markup.tag,"addInlined",{value:function(e,t){var n={},n=(n["language-"+t]={pattern:/(^<!\[CDATA\[)[\s\S]+?(?=\]\]>$)/i,lookbehind:!0,inside:Prism.languages[t]},n.cdata=/^<!\[CDATA\[|\]\]>$/i,{"included-cdata":{pattern:/<!\[CDATA\[[\s\S]*?\]\]>/i,inside:n}}),t=(n["language-"+t]={pattern:/[\s\S]+/,inside:Prism.languages[t]},{});t[e]={pattern:RegExp(/(<__[^>]*>)(?:<!\[CDATA\[(?:[^\]]|\](?!\]>))*\]\]>|(?!<!\[CDATA\[)[\s\S])*?(?=<\/__>)/.source.replace(/__/g,function(){return e}),"i"),lookbehind:!0,greedy:!0,inside:n},Prism.languages.insertBefore("markup","cdata",t)}}),Object.defineProperty(Prism.languages.markup.tag,"addAttribute",{value:function(e,t){Prism.languages.markup.tag.inside["special-attr"].push({pattern:RegExp(/(^|["'\s])/.source+"(?:"+e+")"+/\s*=\s*(?:"[^"]*"|'[^']*'|[^\s'">=]+(?=[\s>]))/.source,"i"),lookbehind:!0,inside:{"attr-name":/^[^\s=]+/,"attr-value":{pattern:/=[\s\S]+/,inside:{value:{pattern:/(^=\s*(["']|(?!["'])))\S[\s\S]*(?=\2$)/,lookbehind:!0,alias:[t,"language-"+t],inside:Prism.languages[t]},punctuation:[{pattern:/^=/,alias:"attr-equals"},/"|'/]}}}})}}),Prism.languages.html=Prism.languages.markup,Prism.languages.mathml=Prism.languages.markup,Prism.languages.svg=Prism.languages.markup,Prism.languages.xml=Prism.languages.extend("markup",{}),Prism.languages.ssml=Prism.languages.xml,Prism.languages.atom=Prism.languages.xml,Prism.languages.rss=Prism.languages.xml,function(e){var t=/(?:"(?:\\(?:\r\n|[\s\S])|[^"\\\r\n])*"|'(?:\\(?:\r\n|[\s\S])|[^'\\\r\n])*')/,t=(e.languages.css={comment:/\/\*[\s\S]*?\*\//,atrule:{pattern:RegExp("@[\\w-](?:"+/[^;{\s"']|\s+(?!\s)/.source+"|"+t.source+")*?"+/(?:;|(?=\s*\{))/.source),inside:{rule:/^@[\w-]+/,"selector-function-argument":{pattern:/(\bselector\s*\(\s*(?![\s)]))(?:[^()\s]|\s+(?![\s)])|\((?:[^()]|\([^()]*\))*\))+(?=\s*\))/,lookbehind:!0,alias:"selector"},keyword:{pattern:/(^|[^\w-])(?:and|not|only|or)(?![\w-])/,lookbehind:!0}}},url:{pattern:RegExp("\\burl\\((?:"+t.source+"|"+/(?:[^\\\r\n()"']|\\[\s\S])*/.source+")\\)","i"),greedy:!0,inside:{function:/^url/i,punctuation:/^\(|\)$/,string:{pattern:RegExp("^"+t.source+"$"),alias:"url"}}},selector:{pattern:RegExp("(^|[{}\\s])[^{}\\s](?:[^{};\"'\\s]|\\s+(?![\\s{])|"+t.source+")*(?=\\s*\\{)"),lookbehind:!0},string:{pattern:t,greedy:!0},property:{pattern:/(^|[^-\w\xA0-\uFFFF])(?!\s)[-_a-z\xA0-\uFFFF](?:(?!\s)[-\w\xA0-\uFFFF])*(?=\s*:)/i,lookbehind:!0},important:/!important\b/i,function:{pattern:/(^|[^-a-z0-9])[-a-z0-9]+(?=\()/i,lookbehind:!0},punctuation:/[(){};:,]/},e.languages.css.atrule.inside.rest=e.languages.css,e.languages.markup);t&&(t.tag.addInlined("style","css"),t.tag.addAttribute("style","css"))}(Prism),Prism.languages.clike={comment:[{pattern:/(^|[^\\])\/\*[\s\S]*?(?:\*\/|$)/,lookbehind:!0,greedy:!0},{pattern:/(^|[^\\:])\/\/.*/,lookbehind:!0,greedy:!0}],string:{pattern:/(["'])(?:\\(?:\r\n|[\s\S])|(?!\1)[^\\\r\n])*\1/,greedy:!0},"class-name":{pattern:/(\b(?:class|extends|implements|instanceof|interface|new|trait)\s+|\bcatch\s+\()[\w.\\]+/i,lookbehind:!0,inside:{punctuation:/[.\\]/}},keyword:/\b(?:break|catch|continue|do|else|finally|for|function|if|in|instanceof|new|null|return|throw|try|while)\b/,boolean:/\b(?:false|true)\b/,function:/\b\w+(?=\()/,number:/\b0x[\da-f]+\b|(?:\b\d+(?:\.\d*)?|\B\.\d+)(?:e[+-]?\d+)?/i,operator:/[<>]=?|[!=]=?=?|--?|\+\+?|&&?|\|\|?|[?*/~^%]/,punctuation:/[{}[\];(),.:]/},Prism.languages.javascript=Prism.languages.extend("clike",{"class-name":[Prism.languages.clike["class-name"],{pattern:/(^|[^$\w\xA0-\uFFFF])(?!\s)[_$A-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*(?=\.(?:constructor|prototype))/,lookbehind:!0}],keyword:[{pattern:/((?:^|\})\s*)catch\b/,lookbehind:!0},{pattern:/(^|[^.]|\.\.\.\s*)\b(?:as|assert(?=\s*\{)|async(?=\s*(?:function\b|\(|[$\w\xA0-\uFFFF]|$))|await|break|case|class|const|continue|debugger|default|delete|do|else|enum|export|extends|finally(?=\s*(?:\{|$))|for|from(?=\s*(?:['"]|$))|function|(?:get|set)(?=\s*(?:[#\[$\w\xA0-\uFFFF]|$))|if|implements|import|in|instanceof|interface|let|new|null|of|package|private|protected|public|return|static|super|switch|this|throw|try|typeof|undefined|var|void|while|with|yield)\b/,lookbehind:!0}],function:/#?(?!\s)[_$a-zA-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*(?=\s*(?:\.\s*(?:apply|bind|call)\s*)?\()/,number:{pattern:RegExp(/(^|[^\w$])/.source+"(?:"+/NaN|Infinity/.source+"|"+/0[bB][01]+(?:_[01]+)*n?/.source+"|"+/0[oO][0-7]+(?:_[0-7]+)*n?/.source+"|"+/0[xX][\dA-Fa-f]+(?:_[\dA-Fa-f]+)*n?/.source+"|"+/\d+(?:_\d+)*n/.source+"|"+/(?:\d+(?:_\d+)*(?:\.(?:\d+(?:_\d+)*)?)?|\.\d+(?:_\d+)*)(?:[Ee][+-]?\d+(?:_\d+)*)?/.source+")"+/(?![\w$])/.source),lookbehind:!0},operator:/--|\+\+|\*\*=?|=>|&&=?|\|\|=?|[!=]==|<<=?|>>>?=?|[-+*/%&|^!=<>]=?|\.{3}|\?\?=?|\?\.?|[~:]/}),Prism.languages.javascript["class-name"][0].pattern=/(\b(?:class|extends|implements|instanceof|interface|new)\s+)[\w.\\]+/,Prism.languages.insertBefore("javascript","keyword",{regex:{pattern:RegExp(/((?:^|[^$\w\xA0-\uFFFF."'\])\s]|\b(?:return|yield))\s*)/.source+/\//.source+"(?:"+/(?:\[(?:[^\]\\\r\n]|\\.)*\]|\\.|[^/\\\[\r\n])+\/[dgimyus]{0,7}/.source+"|"+/(?:\[(?:[^[\]\\\r\n]|\\.|\[(?:[^[\]\\\r\n]|\\.|\[(?:[^[\]\\\r\n]|\\.)*\])*\])*\]|\\.|[^/\\\[\r\n])+\/[dgimyus]{0,7}v[dgimyus]{0,7}/.source+")"+/(?=(?:\s|\/\*(?:[^*]|\*(?!\/))*\*\/)*(?:$|[\r\n,.;:})\]]|\/\/))/.source),lookbehind:!0,greedy:!0,inside:{"regex-source":{pattern:/^(\/)[\s\S]+(?=\/[a-z]*$)/,lookbehind:!0,alias:"language-regex",inside:Prism.languages.regex},"regex-delimiter":/^\/|\/$/,"regex-flags":/^[a-z]+$/}},"function-variable":{pattern:/#?(?!\s)[_$a-zA-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*(?=\s*[=:]\s*(?:async\s*)?(?:\bfunction\b|(?:\((?:[^()]|\([^()]*\))*\)|(?!\s)[_$a-zA-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*)\s*=>))/,alias:"function"},parameter:[{pattern:/(function(?:\s+(?!\s)[_$a-zA-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*)?\s*\(\s*)(?!\s)(?:[^()\s]|\s+(?![\s)])|\([^()]*\))+(?=\s*\))/,lookbehind:!0,inside:Prism.languages.javascript},{pattern:/(^|[^$\w\xA0-\uFFFF])(?!\s)[_$a-z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*(?=\s*=>)/i,lookbehind:!0,inside:Prism.languages.javascript},{pattern:/(\(\s*)(?!\s)(?:[^()\s]|\s+(?![\s)])|\([^()]*\))+(?=\s*\)\s*=>)/,lookbehind:!0,inside:Prism.languages.javascript},{pattern:/((?:\b|\s|^)(?!(?:as|async|await|break|case|catch|class|const|continue|debugger|default|delete|do|else|enum|export|extends|finally|for|from|function|get|if|implements|import|in|instanceof|interface|let|new|null|of|package|private|protected|public|return|set|static|super|switch|this|throw|try|typeof|undefined|var|void|while|with|yield)(?![$\w\xA0-\uFFFF]))(?:(?!\s)[_$a-zA-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*\s*)\(\s*|\]\s*\(\s*)(?!\s)(?:[^()\s]|\s+(?![\s)])|\([^()]*\))+(?=\s*\)\s*\{)/,lookbehind:!0,inside:Prism.languages.javascript}],constant:/\b[A-Z](?:[A-Z_]|\dx?)*\b/}),Prism.languages.insertBefore("javascript","string",{hashbang:{pattern:/^#!.*/,greedy:!0,alias:"comment"},"template-string":{pattern:/`(?:\\[\s\S]|\$\{(?:[^{}]|\{(?:[^{}]|\{[^}]*\})*\})+\}|(?!\$\{)[^\\`])*`/,greedy:!0,inside:{"template-punctuation":{pattern:/^`|`$/,alias:"string"},interpolation:{pattern:/((?:^|[^\\])(?:\\{2})*)\$\{(?:[^{}]|\{(?:[^{}]|\{[^}]*\})*\})+\}/,lookbehind:!0,inside:{"interpolation-punctuation":{pattern:/^\$\{|\}$/,alias:"punctuation"},rest:Prism.languages.javascript}},string:/[\s\S]+/}},"string-property":{pattern:/((?:^|[,{])[ \t]*)(["'])(?:\\(?:\r\n|[\s\S])|(?!\2)[^\\\r\n])*\2(?=\s*:)/m,lookbehind:!0,greedy:!0,alias:"property"}}),Prism.languages.insertBefore("javascript","operator",{"literal-property":{pattern:/((?:^|[,{])[ \t]*)(?!\s)[_$a-zA-Z\xA0-\uFFFF](?:(?!\s)[$\w\xA0-\uFFFF])*(?=\s*:)/m,lookbehind:!0,alias:"property"}}),Prism.languages.markup&&(Prism.languages.markup.tag.addInlined("script","javascript"),Prism.languages.markup.tag.addAttribute(/on(?:abort|blur|change|click|composition(?:end|start|update)|dblclick|error|focus(?:in|out)?|key(?:down|up)|load|mouse(?:down|enter|leave|move|out|over|up)|reset|resize|scroll|select|slotchange|submit|unload|wheel)/.source,"javascript")),Prism.languages.js=Prism.languages.javascript,function(){var l,u,g,c,e;void 0!==Prism&&"undefined"!=typeof document&&(Element.prototype.matches||(Element.prototype.matches=Element.prototype.msMatchesSelector||Element.prototype.webkitMatchesSelector),l={js:"javascript",py:"python",rb:"ruby",ps1:"powershell",psm1:"powershell",sh:"bash",bat:"batch",h:"c",tex:"latex"},c="pre[data-src]:not(["+(u="data-src-status")+'="loaded"]):not(['+u+'="'+(g="loading")+'"])',Prism.hooks.add("before-highlightall",function(e){e.selector+=", "+c}),Prism.hooks.add("before-sanity-check",function(e){var r,t,n,a,s,i,o=e.element;o.matches(c)&&(e.code="",o.setAttribute(u,g),(r=o.appendChild(document.createElement("CODE"))).textContent="Loading…",t=o.getAttribute("data-src"),"none"===(e=e.language)&&(n=(/\.(\w+)$/.exec(t)||[,"none"])[1],e=l[n]||n),Prism.util.setLanguage(r,e),Prism.util.setLanguage(o,e),(n=Prism.plugins.autoloader)&&n.loadLanguages(e),n=t,a=function(e){o.setAttribute(u,"loaded");var t,n,a=function(e){var t,n;if(e=/^\s*(\d+)\s*(?:(,)\s*(?:(\d+)\s*)?)?$/.exec(e||""))return t=Number(e[1]),n=e[2],e=e[3],n?e?[t,Number(e)]:[t,void 0]:[t,t]}(o.getAttribute("data-range"));a&&(t=e.split(/\r\n?|\n/g),n=a[0],a=null==a[1]?t.length:a[1],n<0&&(n+=t.length),n=Math.max(0,Math.min(n-1,t.length)),a<0&&(a+=t.length),a=Math.max(0,Math.min(a,t.length)),e=t.slice(n,a).join("\n"),o.hasAttribute("data-start")||o.setAttribute("data-start",String(n+1))),r.textContent=e,Prism.highlightElement(r)},s=function(e){o.setAttribute(u,"failed"),r.textContent=e},(i=new XMLHttpRequest).open("GET",n,!0),i.onreadystatechange=function(){4==i.readyState&&(i.status<400&&i.responseText?a(i.responseText):400<=i.status?s("✖ Error "+i.status+" while fetching file: "+i.statusText):s("✖ Error: File does not exist or is empty"))},i.send(null))}),e=!(Prism.plugins.fileHighlight={highlight:function(e){for(var t,n=(e||document).querySelectorAll(c),a=0;t=n[a++];)Prism.highlightElement(t)}}),Prism.fileHighlight=function(){e||(console.warn("Prism.fileHighlight is deprecated. Use `Prism.plugins.fileHighlight.highlight` instead."),e=!0),Prism.plugins.fileHighlight.highlight.apply(this,arguments)})}();
Prism.languages.sql={comment:{pattern:/(^|[^\\])(?:\/\*[\s\S]*?\*\/|(?:--|\/\/|#).*)/,lookbehind:!0},variable:[{pattern:/@(["'`])(?:\\[\s\S]|(?!\1)[^\\])+\1/,greedy:!0},/@[\w.$]+/],string:{pattern:/(^|[^@\\])("|')(?:\\[\s\S]|(?!\2)[^\\]|\2\2)*\2/,greedy:!0,lookbehind:!0},identifier:{pattern:/(^|[^@\\])`(?:\\[\s\S]|[^`\\]|``)*`/,greedy:!0,lookbehind:!0,inside:{punctuation:/^`|`$/}},function:/\b(?:AVG|COUNT|FIRST|FORMAT|LAST|LCASE|LEN|MAX|MID|MIN|MOD|NOW|ROUND|SUM|UCASE)(?=\s*\()/i,keyword:/\b(?:ACTION|ADD|AFTER|ALGORITHM|ALL|ALTER|ANALYZE|ANY|APPLY|AS|ASC|AUTHORIZATION|AUTO_INCREMENT|BACKUP|BDB|BEGIN|BERKELEYDB|BIGINT|BINARY|BIT|BLOB|BOOL|BOOLEAN|BREAK|BROWSE|BTREE|BULK|BY|CALL|CASCADED?|CASE|CHAIN|CHAR(?:ACTER|SET)?|CHECK(?:POINT)?|CLOSE|CLUSTERED|COALESCE|COLLATE|COLUMNS?|COMMENT|COMMIT(?:TED)?|COMPUTE|CONNECT|CONSISTENT|CONSTRAINT|CONTAINS(?:TABLE)?|CONTINUE|CONVERT|CREATE|CROSS|CURRENT(?:_DATE|_TIME|_TIMESTAMP|_USER)?|CURSOR|CYCLE|DATA(?:BASES?)?|DATE(?:TIME)?|DAY|DBCC|DEALLOCATE|DEC|DECIMAL|DECLARE|DEFAULT|DEFINER|DELAYED|DELETE|DELIMITERS?|DENY|DESC|DESCRIBE|DETERMINISTIC|DISABLE|DISCARD|DISK|DISTINCT|DISTINCTROW|DISTRIBUTED|DO|DOUBLE|DROP|DUMMY|DUMP(?:FILE)?|DUPLICATE|ELSE(?:IF)?|ENABLE|ENCLOSED|END|ENGINE|ENUM|ERRLVL|ERRORS|ESCAPED?|EXCEPT|EXEC(?:UTE)?|EXISTS|EXIT|EXPLAIN|EXTENDED|FETCH|FIELDS|FILE|FILLFACTOR|FIRST|FIXED|FLOAT|FOLLOWING|FOR(?: EACH ROW)?|FORCE|FOREIGN|FREETEXT(?:TABLE)?|FROM|FULL|FUNCTION|GEOMETRY(?:COLLECTION)?|GLOBAL|GOTO|GRANT|GROUP|HANDLER|HASH|HAVING|HOLDLOCK|HOUR|IDENTITY(?:COL|_INSERT)?|IF|IGNORE|IMPORT|INDEX|INFILE|INNER|INNODB|INOUT|INSERT|INT|INTEGER|INTERSECT|INTERVAL|INTO|INVOKER|ISOLATION|ITERATE|JOIN|KEYS?|KILL|LANGUAGE|LAST|LEAVE|LEFT|LEVEL|LIMIT|LINENO|LINES|LINESTRING|LOAD|LOCAL|LOCK|LONG(?:BLOB|TEXT)|LOOP|MATCH(?:ED)?|MEDIUM(?:BLOB|INT|TEXT)|MERGE|MIDDLEINT|MINUTE|MODE|MODIFIES|MODIFY|MONTH|MULTI(?:LINESTRING|POINT|POLYGON)|NATIONAL|NATURAL|NCHAR|NEXT|NO|NONCLUSTERED|NULLIF|NUMERIC|OFF?|OFFSETS?|ON|OPEN(?:DATASOURCE|QUERY|ROWSET)?|OPTIMIZE|OPTION(?:ALLY)?|ORDER|OUT(?:ER|FILE)?|OVER|PARTIAL|PARTITION|PERCENT|PIVOT|PLAN|POINT|POLYGON|PRECEDING|PRECISION|PREPARE|PREV|PRIMARY|PRINT|PRIVILEGES|PROC(?:EDURE)?|PUBLIC|PURGE|QUICK|RAISERROR|READS?|REAL|RECONFIGURE|REFERENCES|RELEASE|RENAME|REPEAT(?:ABLE)?|REPLACE|REPLICATION|REQUIRE|RESIGNAL|RESTORE|RESTRICT|RETURN(?:ING|S)?|REVOKE|RIGHT|ROLLBACK|ROUTINE|ROW(?:COUNT|GUIDCOL|S)?|RTREE|RULE|SAVE(?:POINT)?|SCHEMA|SECOND|SELECT|SERIAL(?:IZABLE)?|SESSION(?:_USER)?|SET(?:USER)?|SHARE|SHOW|SHUTDOWN|SIMPLE|SMALLINT|SNAPSHOT|SOME|SONAME|SQL|START(?:ING)?|STATISTICS|STATUS|STRIPED|SYSTEM_USER|TABLES?|TABLESPACE|TEMP(?:ORARY|TABLE)?|TERMINATED|TEXT(?:SIZE)?|THEN|TIME(?:STAMP)?|TINY(?:BLOB|INT|TEXT)|TOP?|TRAN(?:SACTIONS?)?|TRIGGER|TRUNCATE|TSEQUAL|TYPES?|UNBOUNDED|UNCOMMITTED|UNDEFINED|UNION|UNIQUE|UNLOCK|UNPIVOT|UNSIGNED|UPDATE(?:TEXT)?|USAGE|USE|USER|USING|VALUES?|VAR(?:BINARY|CHAR|CHARACTER|YING)|VIEW|WAITFOR|WARNINGS|WHEN|WHERE|WHILE|WITH(?: ROLLUP|IN)?|WORK|WRITE(?:TEXT)?|YEAR)\b/i,boolean:/\b(?:FALSE|NULL|TRUE)\b/i,number:/\b0x[\da-f]+\b|\b\d+(?:\.\d*)?|\B\.\d+\b/i,operator:/[-+*\/=%^~]|&&?|\|\|?|!=?|<(?:=>?|<|>)?|>[>=]?|\b(?:AND|BETWEEN|DIV|ILIKE|IN|IS|LIKE|NOT|OR|REGEXP|RLIKE|SOUNDS LIKE|XOR)\b/i,punctuation:/[;[\]()`,.]/};

// ── SQL syntax highlight overlay ──────────────
const sqlInput      = document.getElementById('sqlInput');
const sqlHighlight  = document.getElementById('sqlHighlightCode');
const sqlPre        = sqlInput?.previousElementSibling; // the <pre>

function syncHighlight() {
  if (!sqlInput || !sqlHighlight) return;
  // Escape HTML so Prism doesn't interpret stray < > as tags
  const raw = sqlInput.value;
  sqlHighlight.textContent = raw;
  if (typeof Prism !== 'undefined') Prism.highlightElement(sqlHighlight);
  // Sync scroll so overlay tracks textarea position
  if (sqlPre) {
    sqlPre.scrollTop  = sqlInput.scrollTop;
    sqlPre.scrollLeft = sqlInput.scrollLeft;
  }
  // Sync height (user may drag resize handle)
  if (sqlPre) sqlPre.style.height = sqlInput.offsetHeight + 'px';
}

// Sync on every input and scroll
sqlInput?.addEventListener('input',  syncHighlight);
sqlInput?.addEventListener('scroll', () => {
  if (sqlPre) {
    sqlPre.scrollTop  = sqlInput.scrollTop;
    sqlPre.scrollLeft = sqlInput.scrollLeft;
  }
});

// Re-highlight when AI populates the textarea
const _origAskLLM = window.doAsk;
// Patch renderTable and doQuery to re-highlight after SQL is set externally
const _sqlInputObserver = new MutationObserver(syncHighlight);
// Watch for programmatic .value changes via a small proxy on restoreInputs / useHistory
const _origRestoreInputs = window.restoreInputs;
function patchSqlValue() {
  const orig = sqlInput.value;
  Object.defineProperty(sqlInput, '_syncNeeded', { get() { return false; }, set(v) { if(v) syncHighlight(); } });
}

// Initial sync on page load
setTimeout(syncHighlight, 0);

</script>
</body>
</html>
