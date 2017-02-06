<?php

namespace AgivSTS;

use GuzzleHttp\Client;
use AgivSTS\Exception\AgivException;
use GuzzleHttp\Exception\ClientException as GuzzleException;

/**
 * The class used to obtain AGIV access token.
 */
class AgivAccessToken {

  // Cache object.
  protected $cache;

  // Cache ID.
  protected $cid;

  // Client ID.
  protected $clientId;

  // Client secret.
  protected $clientSecret;

  // Redirect URI.
  protected $redirectUri;

  // Authorization code.
  protected $code;

  /**
   * Object constructor.
   */
  public function __construct(AgivCacheInterface $cache, array $data) {
    $this->cache = $cache;

    // Set object properties.
    foreach ($this as $property => $value) {
      if (!empty($data[$property])) {
        $this->$property = $data[$property];
      }
    }
  }

  /**
   * Validate object variables.
   */
  public function validate() {
    $missing = [];
    foreach (['cache', 'clientId', 'clientSecret', 'redirectUri'] as $variable_name) {
      if (empty($this->$variable_name)) {
        $missing[] = $variable_name;
      }
    }

    if (!empty($missing)) {
      throw new \AgivException('AgivAccessToken object variables missing: ' . implode(', ', $missing));
    }
  }

  /**
   * Get token.
   */
  public function getToken($no_cache = FALSE) {
    $this->validate();

    if ($no_cache) {
      $token_data = [];
    }
    else {
      $token_data = $this->cache->cacheGet($this->cid);
    }

    $request_time = time();

    // Get new token or refresh the existing one.
    if (empty($token_data['refresh_token'])) {
      $request_params = [
        'grant_type=authorization_code&code=' . $this->code,
        'client_id=' . $this->clientId,
        'client_secret=' . $this->clientSecret,
        'redirect_uri=' . urlencode($this->redirectUri),
      ];
    }
    elseif ($token_data['lifetime']['Expires'] < $request_time) {
      $request_params = [
        'grant_type=refresh_token',
        'refresh_token=' . $token_data['refresh_token'],
        'client_id=' . $this->clientId,
        'client_secret=' . $this->clientSecret,
      ];
    }

    if (!empty($request_params)) {
      $options = [
        'headers' => [
          'Host' => 'oauth.beta.agiv.be',
          'Content-Type' => 'application/x-www-form-urlencoded',
        ],
        'body' => implode(PHP_EOL . '&', $request_params),
      ];

      $client = new Client(['timeout' => 15]);

      try {
        $response = $client->request('POST', 'https://oauth.beta.agiv.be/authorization/ws/oauth/v2/token/', $options);
        $response_str = (string) $response->getBody();
      }
      catch (GuzzleException $e) {
        $response_str = (string) $e->getResponse()->getBody();
      }
      $token_data = json_decode($response_str);

      if (isset($token_data->error)) {
        throw new AgivException(t('An error occurred when trying to get AGIV access token. Type: @type, Description: @description.', [
          '@type' => $token_data->error,
          '@description' => isset($token_data->error_description) ? $token_data->error_description : t('not provided'),
        ]));
      }

      if (isset($token_data->access_token)) {
        $token_data = (array) $token_data;
        $token_data['lifetime'] = [
          'Created' => $request_time,
          'Expires' => $request_time + $token_data['expires_in'],
        ];
        $this->cache->cacheSet($this->cid, $token_data);
      }
      else {
        throw new AgivException(t('Unexpected token service response data: @data', [
          '@data' => print_r($token_data, TRUE),
        ]));
      }
    }
    return $token_data['access_token'];
  }

}
