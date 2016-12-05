<?php

namespace AgivSTS;

use DOMDocument;
use DOMElement;
use DOMXpath;

/**
 * Code breaking class for finding right cryptographic dependencies.
 */
class Codebreaker {

  /**
   * Finds values that match given string when properly converted.
   */
  public function findHmacRef($reference_value = 'jMUWXJCOuY6ghXHiOQy/Ycztn4Q=') {


    $digest_data = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"></SignatureMethod><Reference URI="#_0"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>Za0dgYRyzOwb3mmoMaQRZvuh8sM=</DigestValue></Reference></SignedInfo>';
    /**
    do {
      $secret = uniqid();
      $signature = base64_encode(hash_hmac('sha1', $digest_data, $secret, TRUE));
    } while ($signature != $reference_value);

    kdpm($secret);

    return;

    **/

    $key = base64_decode('fl4qc/csI4YrPK0reoJeFfVcmzIY9ESnqCxSQzbscw4=');

    $secret = $key;

    $signature = base64_encode(hash_hmac('sha1', $digest_data, $secret, TRUE));

    kdpm($signature);
    return;


    $data = [
      'fl4qc/csI4YrPK0reoJeFfVcmzIY9ESnqCxSQzbscw4=',
      'b77a5c561934e089',
      '1744541'
    ];

    $separators = ['?', '&', ':', '/', '+', '-'];

    foreach ($data as $index => $value) {
      foreach ($data as $index2 => $value2) {
        if ($index == $index2) {
          continue;
        }

        foreach ($separators as $sep) {
          $secret = $value . $sep . $value2;
          $signature = base64_encode(hash_hmac('sha1', $digest_data, $secret, TRUE));
          if ($signature == $reference_value) {
            $output = $secret;
            break;
          }
        }
        if (isset($output)) {
          break;
        }
      }
      if (isset($output)) {
        break;
      }
    }

    if (isset($output)) {
      kdpm($output);
    }
    else {
      kdpm('Failure.');
    }


    return;

    $contents = file_get_contents($file);
    // Get contents of all tags.

    if (preg_match_all('#>([^<^' . PHP_EOL . ']*?)</#', $contents, $matches)) {

      foreach ($matches[1] as $match) {

        // Cover all base64 possibilities.
        for ($i = 0; $i < 3; $i++) {
          switch ($i) {
            case 0:
              $secret = $match;
              break;

            case 1:
              $secret = base64_encode($match);
              break;

            case 2:
              $secret = base64_decode($match);
              break;
          }

          $signature = base64_encode(hash_hmac('sha1', $digest_data, $secret, TRUE));
          if ($signature === $reference_value) {
            $output = [
              'value' => $match,
              'method' => $i,
            ];
            break;
          }
        }

        if (isset($output)) {
          break;
        }
      }
    }

    if (isset($output)) {
      kdpm($output);
    }
    else {
      kdpm('Failure.');
    }
  }

  public function psha1($clientSecret, $serverSecret, $sizeBits = 256) {
    $sizeBytes = $sizeBits / 8;

    $hmacKey = $clientSecret;
    $hashSize = 160; // HMAC_SHA1 length is always 160
    $bufferSize = $hashSize / 8 + strlen($serverSecret);
    $i = 0;

    $b1 = $serverSecret;
    $b2 = "";
    $temp = null;
    $psha = array();

    while ($i < $sizeBytes) {
      $b1 = hash_hmac('SHA1', $b1, $hmacKey, true);
      $b2 = $b1 . $serverSecret;
      $temp = hash_hmac('SHA1', $b2, $hmacKey, true);

      for ($j = 0; $j < strlen($temp); $j++) {
        if ($i < $sizeBytes) {
          $psha[$i] = $temp[$j];
          $i++;
        }
        else {
          break;
        }
      }
    }

    return implode("", $psha);
  }

}
