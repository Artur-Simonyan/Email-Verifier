<?php

use EmailVerifier\VerifyMail;

require __DIR__."/../VerifyMail.php";

$emailVerifier = new VerifyMail();

try {
    var_dump($emailVerifier->verify('smnnartur1@gmail.com'));
} catch (Exception $e) {
    echo $e->getMessage();
}