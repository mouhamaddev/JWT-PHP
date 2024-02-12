<?php

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

function generateSecretKey($length = 32) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $key = '';

    for ($i = 0; $i < $length; $i++) {
        $key .= $characters[rand(0, $charactersLength - 1)];
    }

    return $key;
}

function base64UrlEncode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function generateJWT($payload, $secretKey, $expiration = null) {
    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
    $payload['exp'] = $expiration ?? time() + (60 * 60);

    $base64UrlHeader = base64UrlEncode($header);
    $base64UrlPayload = base64UrlEncode(json_encode($payload));

    $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $secretKey, true);
    $base64UrlSignature = base64UrlEncode($signature);

    $token = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
    
    //TODO store_token in db
    
    return $token;
}

function verifyJWT($token, $secretKey) {
    
    //TODO check if token in db
    
    list($headerBase64, $payloadBase64, $signatureBase64) = explode('.', $token);

    $header = json_decode(base64_decode(strtr($headerBase64, '-_', '+/')), true);
    $payload = json_decode(base64_decode(strtr($payloadBase64, '-_', '+/')), true);

    $expectedSignature = hash_hmac('sha256', $headerBase64 . '.' . $payloadBase64, $secretKey, true);
    $expectedSignatureBase64 = base64UrlEncode($expectedSignature);

    if ($expectedSignatureBase64 !== $signatureBase64) {
        return false;
    }

    if (isset($payload['exp']) && $payload['exp'] < time()) {
        return false;
    }

    return true;
}


//USAGE:

// Generate a JWT
$secretKey = generateSecretKey();
$payload = ['user_id' => 123];
$expiration = time() + (60 * 60); // Expire in 1 hour
$jwt = generateJWT($payload, $secretKey, $expiration);

// Verify the JWT
$isTokenValid = verifyJWT($jwt, $secretKey);

if ($isTokenValid) {
    echo "JWT is valid! 🎉";
} else {
    echo "JWT is invalid! 😞";
}


?>
