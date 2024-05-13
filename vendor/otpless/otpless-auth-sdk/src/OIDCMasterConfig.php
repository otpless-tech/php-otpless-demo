<?php

namespace Otpless;

class OIDCMasterConfig
{
    public $issuer;
    public $authorization_endpoint;
    public $token_endpoint;
    public $userinfo_endpoint;
    public $jwks_uri;

    public function __construct(array $attributes)
    {
        $this->issuer = $attributes['issuer'] ?? null;
        $this->authorization_endpoint = $attributes['authorization_endpoint'] ?? null;
        $this->token_endpoint = $attributes['token_endpoint'] ?? null;
        $this->userinfo_endpoint = $attributes['userinfo_endpoint'] ?? null;
        $this->jwks_uri = $attributes['jwks_uri'] ?? null;
    }
}
