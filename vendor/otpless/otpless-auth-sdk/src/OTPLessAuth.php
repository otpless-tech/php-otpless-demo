<?php

namespace Otpless;

require '../vendor/autoload.php';

use Exception;
use Otpless\OIDCMasterConfig;
use Otpless\PublicKeyResponse;
use Otpless\UserDetail;
use Otpless\OtpResponse;
use Otpless\OtpVerificationResponse;
use Otpless\MagicLinkTokens;

use \Firebase\JWT\Key;
use GuzzleHttp\Exception\ClientException;

use GuzzleHttp\Client;
use Firebase\JWT\JWT;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;

class OTPLessAuth
{
    public function decodeIdToken($idToken)
    {
        $client = new Client();
        $authConfig = $this->getConfig($client);

        $keyResponse = $this->getPublicKey($authConfig->jwks_uri, $client);

        $response = $this->decodeJWT($keyResponse['n'], $keyResponse['e'], $idToken);

        return json_encode($response);
    }

    public function verifyCode($code, $clientId, $clientSecret)
    {
        try {
            $client = new Client();
            $authConfig = $this->getConfig($client);

            $tokenEndPoint = $authConfig->token_endpoint;

            $client = new Client();

            $response = $client->post($tokenEndPoint, [
                'form_params' => [
                    'code' => $code,
                    'client_id' => $clientId,
                    'client_secret' => $clientSecret,
                ]
            ]);

            $responseBody = $response->getBody()->getContents();
            $data = json_decode($responseBody, true);

            $keyResponse = $this->getPublicKey($authConfig->jwks_uri, $client);

            $response = $this->decodeJWT($keyResponse['n'], $keyResponse['e'], $data['id_token']);

            return json_encode($response);
        } catch (\Exception  $e) {
            $userDetail = new UserDetail();
            $userDetail->success = false;
            $userDetail->errorMsg = "Something went wrong please try again";

            $userDetailArray = (array) $userDetail;

            return json_encode(array_filter($userDetailArray, function ($value) {
                return $value !== null;
            }));
        }
    }


    public function verifyToken($token, $clientId, $clientSecret)
    {

        try {
            $client = new Client();
            $tokenEndpoint = 'https://oidc.otpless.app/auth/userInfo';

            $response = $client->post($tokenEndpoint, [
                'form_params' => [
                    'token' => $token,
                    'client_id' => $clientId,
                    'client_secret' => $clientSecret,
                ]
            ]);

            $responseBody = $response->getBody()->getContents();
            $data = json_decode($responseBody, true);


            $userDetail = new UserDetail();
            $userDetail->success = true;
            $userDetail->auth_time = $data['auth_time'] ?? null;;
            $userDetail->name = $data['name'] ?? null;;
            $userDetail->phone_number = $data['phone_number'] ?? null;;
            $userDetail->email = $data['email'] ?? null;;
            $userDetail->country_code = $data['country_code'] ?? null;;
            $userDetail->national_phone_number = $data['national_phone_number'] ?? null;;

            return json_encode($userDetail);
        } catch (\Exception  $e) {
            $userDetail = new UserDetail();
            $userDetail->success = false;
            $userDetail->errorMsg = "Something went wrong please try again";

            $userDetailArray = (array) $userDetail;

            return json_encode(array_filter($userDetailArray, function ($value) {
                return $value !== null;
            }));
        }
    }


    public function generateMagicLink($mobile, $email, $clientId, $clientSecret, $redirectURI, $channel)
    {
        try {
            $baseURL = "https://oidc.otpless.app/auth/v1/authorize";
            $queryParams = array(
                "client_id" => $clientId,
                "client_secret" => $clientSecret
            );

            if (!empty($email)) {
                $queryParams["email"] = $email;
            }

            if (!empty($mobile)) {
                $queryParams["mobile_number"] = $mobile;
            }

            if (!empty($redirectURI)) {
                $queryParams["redirect_uri"] = $redirectURI;
            }
            if (!empty($channel)) {
                $queryParams["channel"] = $channel;
            }

            $queryString = http_build_query($queryParams);
            $finalURL = $baseURL . '?' . $queryString;

            $ch = curl_init();

            // Set cURL options
            curl_setopt($ch, CURLOPT_URL, $finalURL);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

            // Execute cURL session and fetch the result
            $responseBody = curl_exec($ch);

            $responseData = json_decode($responseBody, true);

            if (!isset($responseData['requestIds'])) {
                $userDetail = new UserDetail();
                $userDetail->success = false;
                $userDetail->errorMsg = $responseData['message'];

                $userDetailArray = (array) $userDetail;

                return json_encode(array_filter($userDetailArray, function ($value) {
                    return $value !== null;
                }));
            }
            $magicLinkTokens = new MagicLinkTokens($responseData);
            return json_encode($magicLinkTokens);
        } catch (\Exception $e) {
            $userDetail = new UserDetail();
            $userDetail->success = false;
            $userDetail->errorMsg = "Something went wrong please try again";

            $userDetailArray = (array) $userDetail;

            return json_encode(array_filter($userDetailArray, function ($value) {
                return $value !== null;
            }));
        }
    }
    private function getConfig($client)
    {
        $response = $client->get('https://otpless.com/.well-known/openid-configuration');
        $json = $response->getBody()->getContents();

        $oidcConfig = new OIDCMasterConfig(json_decode($json, true));

        return $oidcConfig;
    }

    private function getPublicKey($url, $client)
    {
        $response = $client->get($url);
        $json = $response->getBody()->getContents();

        $responseData = json_decode($json, true);

        $publicKeyResponse = new PublicKeyResponse($responseData);

        return $publicKeyResponse->keys[0];
    }

    public function decodeJWT($n, $e, $jwtToken)
    {
        try {
            $decoded = JWT::decode($jwtToken, new Key($this->createRSAPublicKey($n, $e), 'RS256'));
            $decodedDataArray = (array) $decoded;

            $userDetail = json_decode(json_encode($decodedDataArray), false);

            if (isset($decodedDataArray['authentication_details'])) {
                $decodedDataArray['authentication_details'] = json_decode($decodedDataArray['authentication_details']);
            }

            $res = json_decode(json_encode($decodedDataArray), false);


            $userDetail = new UserDetail();
            $userDetail->success = true;
            $userDetail->auth_time = $res->auth_time ?? null;
            $userDetail->name = $res->name ?? null;;
            $userDetail->phone_number = $res->phone_number ?? null;;
            $userDetail->email = $res->email ?? null;;
            $userDetail->country_code = $res->country_code ?? null;;

            $userDetail->national_phone_number = $res->national_phone_number;

            return $userDetail;
        } catch (\Exception  $e) {
            $userDetail = new UserDetail();
            $userDetail->success = false;
            $userDetail->errorMsg = "Something went wrong please try again";

            $userDetailArray = (array) $userDetail;

            return array_filter($userDetailArray, function ($value) {
                return $value !== null;
            });
        }
    }

    function createRSAPublicKey($n, $e)
    {
        $n = base64_decode(strtr($n, '-_', '+/'));
        $e = base64_decode(strtr($e, '-_', '+/'));

        $publicKey = PublicKeyLoader::load([
            'e' => new BigInteger(bin2hex($e), 16),
            'n' => new BigInteger(bin2hex($n), 16)
        ]);

        return openssl_pkey_get_public($publicKey);
    }


    public function sendOtp($phoneNumber, $email, $orderId, $expiry, $hash, $clientId, $clientSecret, $otpLength, $channel)
    {
        try {
            $url = 'https://auth.otpless.app/auth/otp/v1/send';

            if (isset($phoneNumber) && !is_null($phoneNumber)) {
                $data['phoneNumber'] = $phoneNumber;
            }

            if (isset($email) && !is_null($email)) {
                $data['email'] = $email;
            }
            if (isset($orderId) && !is_null($orderId)) {
                $data['orderId'] = $orderId;
            }

            if (isset($expiry) && !is_null($expiry)) {
                $data['expiry'] = $expiry;
            }

            if (isset($otpLength) && !is_null($otpLength)) {
                $data['otpLength'] = $otpLength;
            }

            if (isset($channel) && !is_null($channel)) {
                $data['channel'] = $channel;
            }


            if (isset($hash) && !is_null($hash)) {
                $data['hash'] = $hash;
            }


            $headers = [
                'clientId: ' . $clientId,
                'clientSecret: ' . $clientSecret,
                'Content-Type: application/json',
            ];

            $ch = curl_init();

            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

            $responseBody = curl_exec($ch);

            if (curl_errno($ch)) {
                throw new \Exception('cURL error: ' . curl_error($ch));
            }

            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

            curl_close($ch);

            $responseData = json_decode($responseBody, true);

            if ($httpCode >= 400) {
                throw new \Exception($responseData['message'] ?? 'Something went wrong', $httpCode);
            }

            $otpResponse = new OtpResponse();
            $otpResponse->orderId = $orderId;

            $otpResponse->refId = $responseData['orderId'] ?? null;
            $otpResponse->orderId = $responseData['orderId']  ?? null;

            $otpResponse->message = "success";

            return json_encode($otpResponse);
        } catch (\Exception $e) {
            return $this->handleExpectionForOtp($e->getMessage());
        }
    }


    public function resendOtp($orderId, $clientId, $clientSecret)
    {
        try {
            $url = 'https://auth.otpless.app/auth/otp/v1/resend';
            $data = [
                'orderId' => $orderId
            ];

            $headers = [
                'clientId: ' . $clientId,
                'clientSecret: ' . $clientSecret,
                'Content-Type: application/json',
            ];

            $ch = curl_init();

            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

            $responseBody = curl_exec($ch);

            if (curl_errno($ch)) {
                throw new \Exception('cURL error: ' . curl_error($ch));
            }

            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

            curl_close($ch);

            $responseData = json_decode($responseBody, true);

            if ($httpCode >= 400) {
                throw new \Exception($responseData['message'] ?? 'Something went wrong', $httpCode);
            }

            $otpResponse = new OtpResponse();
            $otpResponse->orderId = $orderId;
            $otpResponse->refId = $responseData['refId'];
            $otpResponse->message = "success";
            return json_encode($otpResponse);
        } catch (\Exception $e) {
            return $this->handleExpectionForOtp($e->getMessage());
        }
    }


    public function verifyOtp($phoneNumber,$email, $orderId, $otp, $clientId, $clientSecret)
    {
        try {
            $url = 'https://auth.otpless.app/auth/otp/v1/verify';
            $data = [
                'orderId' => $orderId,
                'otp' => $otp,
            ];

            if (isset($phoneNumber) && !is_null($phoneNumber)) {
                $data['phoneNumber'] = $phoneNumber;
            }

            if (isset($email) && !is_null($email)) {
                $data['email'] = $email;
            }

            $headers = [
                'clientId: ' . $clientId,
                'clientSecret: ' . $clientSecret,
                'Content-Type: application/json',
            ];

            $ch = curl_init();

            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

            $responseBody = curl_exec($ch);

            if (curl_errno($ch)) {
                throw new \Exception('cURL error: ' . curl_error($ch));
            }

            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

            curl_close($ch);

            $responseData = json_decode($responseBody, true);

            if ($httpCode >= 400) {
                throw new \Exception($responseData['message'] ?? 'Something went wrong', $httpCode);
            }

            $otpResponse = new OtpVerificationResponse();
            $otpResponse->isOTPVerified = $responseData['isOTPVerified'];
            return json_encode($otpResponse);
        } catch (\Exception $e) {
            return  $this->handleExpectionForOtp($e->getMessage());
        }
    }

    /**helper functions */
    private function handleClientExpectionForOtp(ClientException $e)
    {
        $response = $e->getResponse();
        $body = $response->getBody();
        $errorData = json_decode($body, true);

        $otpResponse = new OtpResponse();
        $otpResponse->success = false;
        $otpResponse->message = $errorData['message'] ?? "Something went wrong";

        $otpResponseArray = (array) $otpResponse;

        return json_encode(array_filter($otpResponseArray, function ($value) {
            return $value !== null;
        }));
    }
    private function handleExpectionForOtp($message)
    {
        $otpResponse = new OtpResponse();
        $otpResponse->success = false;
        $otpResponse->message = $message;

        $otpResponseArray = (array) $otpResponse;

        return json_encode(array_filter($otpResponseArray, function ($value) {
            return $value !== null;
        }));
    }
}
