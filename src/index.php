<?php
require '../vendor/autoload.php';

use Otpless\OTPLessAuth;


function sendOtp($mobile, $email, $orderId, $expiry, $hash, $clientId, $clientSecret, $otpLength, $channel)
{
    $auth = new OTPLessAuth();
    $res = $auth->sendOtp($mobile, $email, $orderId, $expiry, $hash, $clientId, $clientSecret, $otpLength, $channel);
    $data = json_decode($res, true);

    $success = $data['success'];
    if ($success === true) {
        $orderId = $data['orderId'];
    }

    echo $res;
}

function resendOtp($orderId, $clientId, $clientSecret)
{

    $auth = new OTPLessAuth();
    $res = $auth->resendOtp($orderId, $clientId, $clientSecret);
    $data = json_decode($res, true);

    $success = $data['success'];
    if ($success === true) {
        $orderId = $data['orderId'];
    }

    echo $res;
}

function verifyOtp($phoneNumber, $email, $orderId, $otp, $clientId, $clientSecret)
{
    $auth = new OTPLessAuth();
    $res = $auth->verifyOtp($phoneNumber, $email, $orderId, $otp, $clientId, $clientSecret);

    $data = json_decode($res, true);

    $isOTPVerified = $data['isOTPVerified'];
    if ($isOTPVerified) {
        echo "OTP verified";
    } else {
        echo "OTP Not verified";
    }
}

function generateMagicLink($mobile, $email, $clientId, $clientSecret, $redirectURI, $channel)
{
    $auth = new OTPLessAuth();
    $res = $auth->generateMagicLink($mobile, $email, $clientId, $clientSecret, $redirectURI, $channel);
    $data = json_decode($res, true);

    $success = $data['success'];
    $requestId = null;

    if ($success) {
        //magic link genereated succesfully

        $requestIds = $data['requestIds'];
        if (!empty($requestIds) && isset($requestIds[0]['value'])) {
            $requestId = $requestIds[0]['value'];
            // Now you have the value
            echo "requestId: $requestId";
        } else {
            echo "No requestIds found or value is missing in the response.";
        }
    }
}

function verifyCode($code, $clientId, $clientSecret)
{
    $auth = new OTPLessAuth();
    $res = $auth->verifyCode($code, $clientId, $clientSecret);
    $data = json_decode($res, true);

    $success = $data['success'];

    if ($success) {
        //if verify code is true then get mobile and other details
        $mobile = $data['national_phone_number'];
        $countryCode = $data['country_code'];
    }
    echo $res;
}

function verifyToken($token, $clientId, $clientSecret)
{
    $auth = new OTPLessAuth();
    $res = $auth->verifyToken($token, $clientId, $clientSecret);
    $data = json_decode($res, true);

    $success = $data['success'];

    if ($success) {
        //if verify code is true then get mobile and other details
        $mobile = $data['national_phone_number'];
        $countryCode = $data['country_code'];
    }
    echo $res;
}
