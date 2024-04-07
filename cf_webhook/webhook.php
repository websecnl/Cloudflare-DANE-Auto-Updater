// 1. In cloudflare under Notifications / Destinations create a webhook to this file on your server
// 2. In cloudflare under Notifications add new Notification for  'TLS/SSL' either Universal or Dedicated Certificate renewal
// 3. Now the update TLSA script will trigger automatically every time the certificate changes :-)
<?php

// Your shared secret token for verification
$sharedSecret = '64CHARRANDOMHEX'; // Replace with your actual secret token (You can generate it using: openssl rand -hex 64)

// Log file path relative to the script's directory
$logFile = __DIR__ . '/webhook.log'; // 'webhook.log' will be located in the same directory as this script

// Fetch the secret token from the request headers
$requestSecret = isset($_SERVER['HTTP_CF_WEBHOOK_AUTH']) ? $_SERVER['HTTP_CF_WEBHOOK_AUTH'] : '';

if ($sharedSecret === $requestSecret) {
    // The secret matches, proceed with executing the Python script
    $scriptPath = '/root/dane/CF_DANE_AUTOPATCH.py'; // You can replace with your own path to the script

    // Execute the Python script
    $output = shell_exec("python3 $scriptPath");

    // Log the successful execution with timestamp
    $logMessage = "[" . date('Y-m-d H:i:s') . "] Webhook triggered successfully. Output: $output\n";
    file_put_contents($logFile, $logMessage, FILE_APPEND);

    // Log or send the output if necessary
    echo "Script executed. Output:\n$output";

    http_response_code(200); // OK
} else {
    // The request is unauthorized
    http_response_code(401); // Unauthorized
    echo "Unauthorized request.";

    // Log the unauthorized access attempt with timestamp
    $logMessage = "[" . date('Y-m-d H:i:s') . "] Unauthorized webhook access attempt.\n";
    file_put_contents($logFile, $logMessage, FILE_APPEND);
}

?>
