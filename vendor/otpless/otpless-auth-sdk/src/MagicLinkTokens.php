<?php
namespace Otpless;


class MagicLinkTokens{

    public $requestIds;
    public $success = true;


    public function __construct(array $data)
    {
        $this->requestIds = $data['requestIds'];
    }
    
}