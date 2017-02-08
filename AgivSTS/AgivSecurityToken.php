<?php

namespace AgivSTS;

use GuzzleHttp\Client;
use SimpleXMLElement;
use DOMDocument;
use AgivSTS\Exception\AgivException;
use GuzzleHttp\Exception\ClientException as GuzzleException;

/**
 * The security token class.
 */
class AgivSecurityToken extends AgivSTSBase {

  protected $pkPath;
  protected $certPath;
  protected $url;
  protected $realm;
  protected $action;
  protected $passphrase;

  protected $xml;

  protected $lifetime;

  // External cache object.
  protected $cacheObject;

  // Boolyean param indicationg if token was retrieved from cache or not.
  protected $cache;

  // Defaults.
  const CONSTRUCTOR_DEFAULTS = [
    'url' => 'https://auth.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/CertificateMessage',
    'action' => 'Issue',
    'passphrase' => '',
  ];

  // Class namespaces.
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
      if (!isset($data[$key])) {
        $data[$key] = $value;
      }
    }

    // Load object variables.
    parent::__construct($data);

    $this->xml = new DOMDocument();
  }

  /**
   * Getter function.
   */
  public function get($property) {
    if (isset($this->$property)) {
      return $this->$property;
    }
  }

  /**
   * Get cipher value.
   */
  public function getCipher() {
    $cipher = $this->xml->getElementsByTagNameNS(self::XMLNS['xenc'], 'CipherValue')->item(1);
    if ($cipher) {
      return $cipher->textContent;
    }
    return '';

  }

  /**
   * Validate object variables.
   */
  protected function validateVariables() {
    $missing = [];
    foreach (['action', 'url', 'realm', 'certPath', 'pkPath'] as $variable_name) {
      if (empty($this->{$variable_name})) {
        $missing[] = $variable_name;
      }
    }

    if (!empty($missing)) {
      throw new AgivException('Agiv security token object variables missing: ' . implode(', ', $missing));
    }
  }

  /**
   * Load token data.
   *
   * @param string $cache_id
   *   No comment required.
   * @param bool $flush
   *   Should the cache be bypassed and set for newly retrieved token?
   */
  public function load($cache_id = '', $flush = FALSE) {
    if ($flush || !$this->cacheGet($cache_id)) {
      if ($this->requestToken()) {
        $this->cacheSet($cache_id);
      }
    }
  }

  /**
   * Get new token data.
   */
  public function requestToken() {
    // Validate.
    $this->validateVariables();

    // Build request.
    $agivSTSRequest = new AgivSTSRequest([
      'certPath' => $this->certPath,
      'pkPath' => $this->pkPath,
      'passphrase' => $this->passphrase,
      'action' => $this->action,
      'url' => $this->url,
      'realm' => $this->realm,
    ]);

    $client = new Client(['timeout' => isset($GLOBALS['agiv_library_settings']) ? $GLOBALS['agiv_library_settings']['call_timeout'] : 15]);

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
    catch (GuzzleException $e) {
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
    if (is_object($this->cacheObject) && method_exists($this->cacheObject, 'cacheSet')) {
      $this->cacheObject->cacheSet($cache_id, $this);
    }
  }

  /**
   * Get cache.
   */
  protected function cacheGet($cache_id = '') {
    if (is_object($this->cacheObject) && method_exists($this->cacheObject, 'cacheGet')) {
      if ($data = $this->cacheObject->cacheGet($cache_id)) {
        $this->lifetime = $data['lifetime'];
        $this->xml->loadXML($data['xml']);
        $this->cache = TRUE;
        return TRUE;
      }
    }

    return FALSE;
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
      throw new AgivException('No encrypted data can be found in retrieved security token.');
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
