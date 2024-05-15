# Merchant Integration Documentation(Backend PHP Auth SDK)

---

> ## A. OTPLessAuth Dependency
>
> install Below dependency in your project's

```shell
composer require otpless/otpless-auth-sdk
```

you can also get latest version of dependency
at https://packagist.org/packages/otpless/otpless-auth-sdk

---

> ## B. OTPLessAuth class

The `OtplessAuth` class provides methods to integrate OTPLess authentication into your PHP backend application. This
documentation explains the usage of the class and its methods.

### Methods:

---

> ### 1. decodeIdToken

---

This method help to resolve `idToken(JWT token)` which is issued by `OTPLess` which return user detail
from that token also this method verify that token is valid, token should not expired and
issued by only `otpless.com`

##### Method Signature:

```php
decodeIdToken(id_token, client_id, client_secret, audience=None)
```

#### Method Params:

| Params       | Data type | Mandatory | Constraints | Remarks                                                                      |
| ------------ | --------- | --------- | ----------- | ---------------------------------------------------------------------------- |
| idToken      | String    | true      |             | idToken which is JWT token which you get from `OTPLess` by exchange code API |
| clientId     | String    | true      |             | Your OTPLess `Client Id`                                                     |
| clientSecret | String    | true      |             | Your OTPLess `Client Secret`                                                 |

#### Return

Return:
Object Name: UserDetail

```json
{'success': True, 'auth_time': 1697649943, 'phone_number': '+9193******', 'email': 'dev***@gmail.com', 'name': 'Devloper From OTP-less', 'country_code': '+91', 'national_phone_number': '9313******'}
```

> ### 2. verify code

---

This method help to resolve `code` which is return from `OTPLess` which will return user detail
from that code also this method verify that code is valid, code should not expired and
issued by only `otpless.com`

##### Method Signature:

```php
verifyCode(code, client_id, client_secret)
```

#### Method Params:

| Params       | Data type | Mandatory | Constraints | Remarks                           |
| ------------ | --------- | --------- | ----------- | --------------------------------- |
| code         | String    | true      |             | code which you get from `OTPLess` |
| clientId     | String    | true      |             | Your OTPLess `Client Id`          |
| clientSecret | String    | true      |             | Your OTPLess `Client Secret`      |

#### Return

Return:
Object Name: UserDetail

```json
{'success': True, 'auth_time': 1697649943, 'phone_number': '+9193******', 'email': 'dev***@gmail.com', 'name': 'Devloper From OTP-less', 'country_code': '+91', 'national_phone_number': '9313******'}
```



> ### 3. Verify Auth Token

---

This method help to resolve `token` which is issued by `OTPLess` which return user detail
from that token also this method verify that token is valid, token should not expired and
issued by only `otpless.com`

##### Method Signature:

```php
verifyToken(token, client_id, client_secret)
```

#### Method Params:

| Params       | Data type | Mandatory | Constraints | Remarks                            |
| ------------ | --------- | --------- | ----------- | ---------------------------------- |
| token        | String    | true      |             | token which you get from `OTPLess` |
| clientId     | String    | true      |             | Your OTPLess `Client Id`           |
| clientSecret | String    | true      |             | Your OTPLess `Client Secret`       |

#### Return

Return:
Object Name: UserDetail

```json
{'success': True, 'auth_time': 1697649943, 'phone_number': '+9193******', 'email': 'dev***@gmail.com', 'name': 'Devloper From OTP-less', 'country_code': '+91', 'national_phone_number': '9313******'}
```

---

> ### 4. Generate Magic link

---

The Authorization Endpoint initiates the authentication process by sending a `magic link` to the user's WhatsApp or email, based on the provided contact information. This link is used to verify the identity of the user. Upon the user's action on this link, they are redirected to the specified URI with an authorization code included in the redirection.

##### Method Signature:

```php
generateMagicLink(mobile_number, email, client_id, client_secret,redirect_uri,channel)
```

#### Method Params:


| Params        | Data type | Mandatory | Constraints                                       | Remarks                                                                                               |
| ------------- | --------- | --------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| channel       | String    | false     | if no channel given WHATSAPP is chosen as default | WHATSAPP/SMS                                                                                          |
| mobile_number | String    | false     | At least one required                             | The user's mobile number for authentication in the format: country code + number (e.g., 91XXXXXXXXXX) |
| email         | String    | false     | At least one required                             | The user's email address for authentication.                                                          |
| redirect_uri  | String    | true      |                                                   | The URL to which the user will be redirected after authentication. This should be URL-encoded         |
| clientId      | String    | true      |                                                   | Your OTPLess `Client Id`                                                                              |
| clientSecret  | String    | true      |                                                   | Your OTPLess `Client Secret`                                                                          |

#### Return

Return:
Object Name: RquestIds

```json
{"requestIds":[{"type":"MOBILE","value":"ac48690347c24c0b8b54270590392b2a"}],"success":true}
```


### Example of usage

```php

require '../vendor/autoload.php';

use Otpless\OTPLessAuth; 

// Your ID token to decode
$token = 'your token here';

$clientId = 'your client id here';
$clientSecret = 'your client secret here';
// Initialize the library class
$auth = new OtplessAuth(); 


$auth->verifyToken($token,$clientId,$clientSecret);
```




> ### 5. Send OTP

This method help to send OTP to your users and OTP issued by only `otpless.com`

```php
sendOtp(phoneNumber, email, orderId, expiry, hash, clientId, clientSecret, otpLength, channel)
```

#### Method Params:


| Params       | Data type | Mandatory | Constraints | Remarks                           |
| ------------ | --------- | --------- | ----------- | --------------------------------- |
| phoneNumber  | String    | true      |             | Mobile Number of your users       |
| email        | String    | true      |             | Mail Id of your users             |
| channel      | String    | false     |             | WHATSAPP, SMS                     |
| hash         | String    | true      |             | Your mobile application Hash      |
| orderId      | String    | true      |             | Unique Order id                   |
| expiry       | Int       | false     |             | OTP expiry in sec                 |
| otpLength    | String    | false     |             | Values like 6 or 4                |
| clientId     | String    | true      |             | Your OTPLess `Client Id`          |
| clientSecret | String    | true      |             | Your OTPLess `Client Secret`      |



#### Return

```json
{"success":true,"orderId":"V112444","refId":"108","message":"success"}
```
---

> ### 6. ReSend OTP

This method help to resend OTP to your users and OTP issued by only `otpless.com`


```php
resendOtp(orderId, clientId, clientSecret)
```
#### Method Params:

| Params       | Data type | Mandatory | Constraints | Remarks                               |
| ------------ | --------- | --------- | ----------- | --------------------------------------|
| orderId      | String    | true      |             | Unique Order id(same as send method)  |
| clientId     | String    | true      |             | Your OTPLess `Client Id`              |
| clientSecret | String    | true      |             | Your OTPLess `Client Secret`          |

#### Return

```json
{"success":true,"orderId":"V112444","refId":"108","message":"success"}
```
---


> ### 7. Verify OTP

This method help to Verify OTP to your users and OTP issued by only `otpless.com`

##### Method Signature:

```php
verifyOtp(phoneNumber,email, orderId, otp, clientId, clientSecret)
```

#### Method Params:

| Params       | Data type | Mandatory | Constraints | Remarks                               |
| ------------ | --------- | --------- | ----------- | --------------------------------------|
| email        | String    | true      |             | Mail Id of your users                 |
| phoneNumber  | String    | true      |             | Mobile Number of your users           |
| orderId      | String    | true      |             | Unique Order id                       |
| otp          | String    | true      |             | Enter otp here                        |
| clientId     | String    | true      |             | Your OTPLess `Client Id`              |
| clientSecret | String    | true      |             | Your OTPLess `Client Secret`          |


```json
{"success":true,"isOTPVerified":true}
```