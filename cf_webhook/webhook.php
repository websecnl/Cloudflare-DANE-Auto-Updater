// 1. In cloudflare under Notifications / Destinations create a webhook to this file on your server
// 2. In cloudflare under Notifications add new Notification for  'TLS/SSL' either Universal or Dedicated Certificate renewal
// 3. Now the update TLSA script will trigger automatically every time the certificate changes :-)

<?php

// Your shared secret token for verification
$sharedSecret = '64CHARRANDOMHEX'; // Replace with your actual secret token

// Fetch the secret token from the request headers
$requestSecret = isset($_SERVER['HTTP_CF_WEBHOOK_AUTH']) ? $_SERVER['HTTP_CF_WEBHOOK_AUTH'] : '';

if ($sharedSecret === $requestSecret) {
    // The secret matches, proceed with executing the Python script
    $scriptPath = '/root/dane/CF_DANE_AUTOPATCH.py'; // You can replace with your own path ot the script

    // Execute the Python script
    $output = shell_exec("python3 $scriptPath");

    // Log or send the output if necessary
    echo "Script executed. Output:\n$output";

    http_response_code(200); // OK
} else {
    // The request is unauthorized
    http_response_code(401); // Unauthorized
    echo "Unauthorized request.";
}

?>
