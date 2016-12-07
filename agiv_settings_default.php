<?php

/**
 * @file
 * Agiv STS library settings.
 *
 * To customize, create a copy and save in the same location with
 * agiv_settings.php name.
 */

$agiv_library_settings = [];

// Guzzle will timeout after the request
// takes more than this time in seconds.
$agiv_library_settings['call_timeout'] = 30;

// This many additional attempts will be made
// after a "failed security" call to a service endpoint.
// Each attempt acquires a new security token
// and updates token cache.
$agiv_library_settings['max_service_attempts'] = 1;
