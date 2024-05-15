<?php
namespace Otpless;

class PublicKeyResponse
{
    public $keys;

    public function __construct(array $data)
    {
        $this->keys = $data['keys'];
    }
}

class Key
{
    public $kty;
    public $kid;
    public $n;
    public $e;

    public function __construct(array $data)
    {
        $this->kty = $data['kty'];
        $this->kid = $data['kid'];
        $this->n = $data['n'];
        $this->e = $data['e'];
    }
}
