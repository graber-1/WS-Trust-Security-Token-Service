<?php

namespace AgivSTS;

require_once __DIR__ . '/../../guzzlehttp/guzzle/src/Client.php';
require_once __DIR__ . '/AgivSTSRequest.php';

use GuzzleHttp\Client;
use SimpleXMLElement;
use DOMDocument;
use DOMXpath;

/**
 * The security token class.
 */
class AgivSecurityToken {

  protected $pkPath;
  protected $certPath;
  protected $url;
  protected $realm;
  protected $passphrase;

  protected $xml;
  protected $xpath;

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
    $this->xpath = new DOMXpath($this->xml);
  }

  /**
   * Load token data.
   */
  public function load($cache_id = '') {
    if (!$this->cacheGet($cache_id)) {
      if ($this->requestToken()) {
        $this->cacheSet();
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
      return $this->parseResponse((string) $response->getBody());
    }
    catch (\Exception $e) {
      $xml = (string) $e->getResponse()->getBody();
      $this->parseResponse($xml);
    }

  }

  /**
   * Parse xml response.
   */
  private function parseResponse($response) {
    $this->xml->loadXML($response);

    // Error handling.
    $fault = $this->xml->getElementsByTagNameNS(self::XMLNS['s'], 'Fault')->item(0);
    if (!empty($fault)) {
      $error_data = [
        'reason' => 's:Reason/s:Text',
        'code' => 's:Code/s:Value',
        'subcode' => 's:Code/s:Subcode/s:Value',
      ];

      foreach ($error_data as $key => $query) {
        $result = $this->xpath->query($query, $fault);
        if ($result->length) {
          $error_data[$key] = (string) $result->item(0)->nodeValue;
        }
        else {
          $error_data[$key] = 'not provided';
        }
      }
      throw new \Exception(vsprintf('Agiv STS Error: %s Code: %s, subcode: %s.', $error_data));
    }
    else {
      $this->lifetime = [];
      $lifetime = $this->xml->getElementsByTagNameNS(self::XMLNS['trust'], 'Lifetime');
      if ($lifetime->length) {
        foreach ($lifetime->item(0)->childNodes as $node) {
          $this->lifetime[$node->localName] = strtotime(substr($node->nodeValue, 0, strpos($node->nodeValue, '.')) . ' UTC');
        }
      }
      $this->cache = FALSE;
      return TRUE;
    }
    return FALSE;
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
        return TRUE;
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
   * Test function to get xml string.
   */
  public function retrieveXml() {
    $agivSTSRequest = new AgivSTSRequest([
      'certPath' => $this->certPath,
      'pkPath' => $this->pkPath,
    ]);

    return $agivSTSRequest->xmlOutput();
  }

}
