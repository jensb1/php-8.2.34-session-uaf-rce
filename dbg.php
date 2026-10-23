<?php
header("Content-Type: text/plain");
echo "post_fields=" . count($_POST) . "\n";
echo "files=" . count($_FILES) . "\n";
echo "peak_mem=" . memory_get_peak_usage(true) . "\n";
