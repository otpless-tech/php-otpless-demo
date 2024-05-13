<?php

namespace Otpless;


class OtpVerificationResponse
{
    public $success = true;
    public $isOTPVerified;
    public $reason;
    public $errorMessage;
}
