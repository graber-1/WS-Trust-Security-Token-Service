<?php

namespace AgivSTS;

use DOMDocument;
use AgivSTS\Exception\AgivException;
use GuzzleHttp\Exception\ClientException as GuzzleException;

/**
 * The security token class.
 */
class AgivSecurityToken extends AgivSTSBase {

  /**
   * Primary key file path.
   *
   * @var string
   */
  protected $pkPath;

  /**
   * Certificate file path.
   *
   * @var string
   */
  protected $certPath;

  /**
   * Secutity token service URL.
   *
   * @var string
   */
  protected $url;

  /**
   * Service realm.
   *
   * @var string
   */
  protected $realm;

  /**
   * Action performed, default: Issue.
   *
   * @var string
   */
  protected $action;

  /**
   * PK passphrase.
   *
   * @var string
   */
  protected $passphrase;

  /**
   * Document xml object.
   *
   * @var \DOMDocument
   */
  protected $xml;

  /**
   * Acquired token lifetime.
   *
   * @var array
   *   Elements: Created, Expires timestamps.
   */
  protected $lifetime;

  /**
   * Raw STS service output.
   *
   * @var string
   */
  protected $rawData;

  /**
   * Preconfigured HTTP client (Guzzle).
   *
   * @var \GuzzleHttp\Client
   */
  protected $httpClient;

  /**
   * External cache object.
   *
   * @var \AgivSTS\AgivCacheInterface
   */
  protected $cacheObject;

  /**
   * Boolyean param indicationg if token was retrieved from cache or not.
   *
   * @var bool
   */
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
   * Initialize object and create its xml document.
   *
   * @param array $data
   *   Associative array of object property values.
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
   *
   * @param string $property
   *   The name of the retrieved property.
   *
   * @return mixed
   *   Value of the property or null.
   */
  public function get($property) {
    if (isset($this->$property)) {
      return $this->$property;
    }
  }

  /**
   * Get SAML assertion XML string.
   *
   * @return string
   *   Security token response XML string.
   */
  public function getAssertion() {
    $token = $this->xml->getElementsByTagNameNS(self::XMLNS['trust'], 'RequestSecurityTokenResponse')->item(0);
    if ($token) {
      $newDoc = new DOMDocument();
      $importedNode = $newDoc->importNode($token, TRUE);
      $newDoc->appendChild($importedNode);
      return $newDoc->saveXML();
    }
    return '';
  }

  /**
   * Validate object variables.
   */
  protected function validateVariables() {
    $missing = [];
    foreach (['action', 'url', 'realm', 'certPath', 'pkPath', 'httpClient'] as $variable_name) {
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

    $options = [
      'headers' => [
        'Content-Type' => 'application/soap+xml; charset=utf-8',
      ],
      'body' => $agivSTSRequest->xmlOutput(),
    ];

    try {
      $response = $this->httpClient->post($this->url, $options);
      $this->rawData = (string) $response->getBody();
    }
    catch (GuzzleException $e) {
      $this->rawData = (string) $e->getResponse()->getBody();
    }

    $this->xml->loadXML($this->rawData);
    if ($this->checkResponse()) {
      $this->parseResponse();
      return TRUE;
    }
    return FALSE;
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
   *
   * @param string $cache_id
   *   Cache identifier.
   */
  protected function cacheSet($cache_id = '') {
    if (is_object($this->cacheObject) && method_exists($this->cacheObject, 'cacheSet')) {
      $this->cacheObject->cacheSet($cache_id, $this);
    }
  }

  /**
   * Get cache.
   *
   * @param string $cache_id
   *   Cache identifier.
   *
   * @return bool
   *   Did the attempt to load the token from cache succeeded?
   */
  protected function cacheGet($cache_id = '') {
    if (is_object($this->cacheObject) && method_exists($this->cacheObject, 'cacheGet')) {
      if ($data = $this->cacheObject->cacheGet($cache_id)) {
        $this->lifetime = $data['lifetime'];
        $this->rawData = $data['xml'];
        $this->xml->loadXML($this->rawData);
        $this->cache = TRUE;
        return TRUE;
      }
    }

    return FALSE;
  }

  /**
   * Inject security token to XML document.
   *
   * @param \DOMElement $element
   *   The element where the security token should be appended.
   * @param \DOMDocument $document
   *   The parent document of $element parameter.
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
   *
   * @return \DOMElement
   *   The token reference element.
   */
  public function getReference() {
    $reference = $this->xml->getElementsByTagNameNS(self::XMLNS['o'], 'SecurityTokenReference')->item(1);
    return $reference;
  }

  /**
   * Get binary secret.
   *
   * @return string
   *   Binary secret string used for hash HMAC method.
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
   *
   * Allows to check xml of the request to STS
   * service without making the request.
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
