<?php

namespace EmailVerifier;

class EmailVerifierConstants {
    /**
     * SMTP port number
     * @var int
     */
    const PORT = 25;

    /**
     * email address for request
     * @var string
     */
    const FROM_EMAIL = "support@smartis.bi";

    /**
     * email address for request
     * @var string
     */
    const MAX_CONNECTION_TIMEOUT = 30;

    /**
     * email address for request
     * @var string
     */
    const STREAM_TIMEOUT = 5;

    /**
     * email address for request
     * @var string
     */
    const STREAM_TIMEOUT_WAIT = 0;

    /**
     * SMTP RFC standard line ending.
     */
    const CRLF = "\r\n";

}