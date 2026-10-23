<?php
header("Content-Type: text/plain");
$s = $_POST['a'];
$r = &$_POST; unset($r['a']);
ob_start(); debug_zval_dump($s); $z=ob_get_clean();
echo "before write: ".$z."\n";
$s[0]='Z';
echo "after write: $s\n";
