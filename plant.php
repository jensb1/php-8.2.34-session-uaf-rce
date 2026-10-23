<?php
header("Content-Type: text/plain");
$mode = $_GET['mode'] ?? 'obj';
if (isset($_GET['sid'])) session_id($_GET['sid']);
session_start();
if ($mode === 'obj') {
    $o = new stdClass();
    $_SESSION['a'] = $o; $_SESSION['b'] = $o;
} elseif ($mode === 'rc32') {
    $o = new stdClass();
    $o->self = $o;                       /* self-ref: O appears inside its own props */
    for ($i = 0; $i < 31; $i++) { $_SESSION["r$i"] = $o; }   /* +31 refs => rc 32 */
} elseif ($mode === 'scalar') {
    $_SESSION['s1'] = 'scalarvalue'; $_SESSION['s2'] = 'another';
}
session_write_close();
echo "planted sid=" . session_id() . " mode=$mode\n";
echo serialize(array_keys($_SESSION)) . "\n";
