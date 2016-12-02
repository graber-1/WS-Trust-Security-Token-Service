<?php

namespace AgivSTS;

require_once __DIR__ . '/../../guzzlehttp/guzzle/src/Client.php';
require_once __DIR__ . '/AgivSTSRequest.php';

use GuzzleHttp\Client;
use SimpleXMLElement;
use DOMDocument;

/**
 * The security token class.
 */
class AgivSecurityToken extends AgivSTSBase {

  protected $pkPath;
  protected $certPath;
  protected $url;
  protected $realm;
  protected $passphrase;

  protected $xml;

  protected $lifetime;

  protected $cache;

  // Defaults.
  const CONSTRUCTOR_DEFAULTS = [
    'url' => 'https://auth.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/CertificateMessage',
    'realm' => 'urn:agiv.be/gipod',
    'action' => 'Issue',
    'passphrase' => '',
  ];

  const XMLNS = [
    's' => 'http://www.w3.org/2003/05/soap-envelope',
    'trust' => 'http://docs.oasis-open.org/ws-sx/ws-trust/200512',
    'xenc' => 'http://www.w3.org/2001/04/xmlenc#',
    'o' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
  ];

  /**
   * Constructor.
   */
  public function __construct(array $data) {
    // Apply defaults.
    foreach (self::CONSTRUCTOR_DEFAULTS as $key => $value) {
      if (is_null($data[$key])) {
        $data[$key] = $value;
      }
    }

    // Load object variables.
    foreach ([
      'pkPath',
      'certPath',
      'url',
      'realm',
      'passphrase',
    ] as $key) {
      if (isset($data[$key])) {
        $this->{$key} = $data[$key];
      }
      else {
        throw new \Exception(sprintf('Security token: %s parameter not provided.', $key));
      }
    }

    $this->xml = new DOMDocument();
  }

  /**
   * Load token data.
   */
  public function load($cache_id = '') {
    if (!$this->cacheGet($cache_id)) {
      if ($this->requestToken()) {
        $this->cacheSet($cache_id);
      }
    }
  }

  /**
   * Get new token data.
   */
  public function requestToken() {
    $agivSTSRequest = new AgivSTSRequest([
      'certPath' => $this->certPath,
      'pkPath' => $this->pkPath,
      'passphrase' => $this->passphrase,
      'action' => $this->action,
      'url' => $this->url,
      'realm' => $this->realm,
    ]);

    $client = new Client(['timeout' => 15]);

    $options = [
      'headers' => [
        'Content-Type' => 'application/soap+xml; charset=utf-8',
      ],
      'body' => $agivSTSRequest->xmlOutput(),
    ];

    try {
      $response = $client->post($this->url, $options);
      $response_str = (string) $response->getBody();
    }
    catch (\Exception $e) {
      $response_str = (string) $e->getResponse()->getBody();
    }

    $this->xml->loadXML($response_str);
    if ($this->checkResponse()) {
      $this->parseResponse();
      return TRUE;
    }

  }

  /**
   * Parse xml response.
   */
  protected function parseResponse() {
    $this->lifetime = [];
    $lifetime = $this->xml->getElementsByTagNameNS(self::XMLNS['trust'], 'Lifetime');
    if ($lifetime->length) {
      foreach ($lifetime->item(0)->childNodes as $node) {
        $this->lifetime[$node->localName] = strtotime(substr($node->nodeValue, 0, strpos($node->nodeValue, '.')) . ' UTC');
      }
    }
    $this->cache = FALSE;
  }

  /**
   * Set cache.
   */
  protected function cacheSet($cache_id = '') {
    $filename = 'cache' . (empty($cache_id) ? '' : '_' . $cache_id) . '.dat';
    $path = __DIR__ . '/cache/' . $filename;
    $data = array(
      'lifetime' => $this->lifetime,
      'xml' => $this->xml->saveXML(),
    );
    file_put_contents($path, serialize($data));
  }

  /**
   * Get cache.
   */
  protected function cacheGet($cache_id = '') {
    $filename = 'cache' . (empty($cache_id) ? '' : '_' . $cache_id) . '.dat';
    $path = __DIR__ . '/cache/' . $filename;
    if (file_exists($path)) {
      $data = unserialize(file_get_contents($path));
      if (isset($data['lifetime']) && $data['lifetime']['Expires'] > time()) {
        $this->lifetime = $data['lifetime'];
        $this->xml->loadXML($data['xml']);
        $this->cache = TRUE;
        return FALSE;
      }
    }
    else {
      return FALSE;
    }
  }

  /**
   * Inject security token to XML document.
   */
  public function injectToken(\DOMElement $element, \DOMDocument $document) {
    $encryptedData = $this->xml->getElementsByTagNameNS(self::XMLNS['xenc'], 'EncryptedData')->item(0);
    if (!empty($encryptedData)) {

      // Inject encrypted data.
      $importedNode = $document->importNode($encryptedData, TRUE);
      $element->appendChild($importedNode);

    }
    else {
      throw new \Exception('No encrypted data can be found in retrieved security token.');
    }
  }

  /**
   * Get token reference element.
   */
  public function getReference() {
    $reference = $this->xml->getElementsByTagNameNS(self::XMLNS['o'], 'SecurityTokenReference')->item(1);
    return $reference;
  }

  /**
   * Get binary secret.
   */
  public function getBinarySecret() {
    $secret = $this->xml->getElementsByTagNameNS(self::XMLNS['trust'], 'BinarySecret')->item(0);
    if ($secret) {
      return $secret->textContent;
    }
    return '';
  }

  /**
   * Test function to get xml string.
   */
  public function retrieveXml() {
    $agivSTSRequest = new AgivSTSRequest([
      'certPath' => $this->certPath,
      'pkPath' => $this->pkPath,
      'url' => $this->url,
    ]);

    return $agivSTSRequest->xmlOutput();
  }

}
