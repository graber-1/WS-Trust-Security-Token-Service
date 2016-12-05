<?php

namespace AgivSTS\Services;

require_once __DIR__ . '/../ServiceDocument.php';
require_once __DIR__ . '/../AgivSecurityToken.php';
require_once __DIR__ . '/../AgivSTSSignature.php';
require_once __DIR__ . '/../../../guzzlehttp/guzzle/src/Client.php';

use AgivSTS\ServiceDocument;
use AgivSTS\AgivSecurityToken;
use AgivSTS\AgivSTSSignature;
use DOMDocument;
use DOMElement;
use GuzzleHttp\Client;

/**
 * Class for accessing Gipod webAPI.
 */
class GipodService extends ServiceDocument {

  const CONSTRUCTOR_DEFAULTS = [
    'action' => 'GetListLocatieHinder',
    'url' => 'https://gipod.agiv.be/Webservice/GipodService.svc/wsfed',
  ];

  const ACTION_BASE = 'http://www.agiv.be/Gipod/2010/06/service/IGipodService/';
  const REPLY_TO = 'http://www.w3.org/2005/08/addressing/anonymous';

  const XMLNS_DEFAULT = 'http://www.agiv.be/Gipod/2010/06/service';

  protected $action;
  protected $url;

  protected $docGuid;

  protected $certPath;
  protected $pkPath;

  // Document security header and signature elements.
  protected $securityHeader;
  protected $signatureElements;

  /**
   * Object constructor.
   */
  public function __construct($data = array()) {
    // Apply defaults.
    foreach (self::CONSTRUCTOR_DEFAULTS as $key => $value) {
      if (is_null($data[$key])) {
        $data[$key] = $value;
      }
    }

    parent::__construct($data);

    // Check if all required values are provided.
    $this->validateVariables();

    // Get security token.
    $this->agivSecurityToken = new AgivSecurityToken([
      'pkPath' => $this->pkPath,
      'certPath' => $this->certPath,
      'realm' => 'urn:agiv.be/gipod',
    ]);

    // Use "test" argument to get test security token that corresponds to responses from "data" folder.
    $this->agivSecurityToken->load('gipod');
  }

  /**
   * Validate object variables.
   */
  protected function validateVariables() {
    $missing = [];
    foreach (['action', 'url', 'certPath', 'pkPath'] as $variable_name) {
      if (empty($this->{$variable_name})) {
        $missing[] = $variable_name;
      }
    }

    if (!empty($missing)) {
      throw new \Exception('Gipod object variables missing: ' . implode(', ', $missing));
    }
  }

  /**
   * Gipod request builder.
   */
  public function buildRequest() {
    // Generate document guid.
    $this->docGuid = self::generateGuid();

    $this->xml = new DOMDocument();
    $this->prepareXml();
    $this->signXml();
  }

  /**
   * Execute request.
   */
  public function call($action = FALSE) {
    if ($action) {
      $this->action = $action;
    }

    $this->buildRequest();

    $client = new Client(['timeout' => 15]);

    $options = [
      'headers' => [
        'Content-Type' => 'application/soap+xml; charset=utf-8',
      ],
      'body' => $this->xmlOutput(),
    ];

    try {
      $response = $client->post($this->url, $options);
      $response_str = (string) $response->getBody();
    }
    catch (\Exception $e) {
      $response_str = $e->getResponse()->getBody();
    }

    $this->xml->loadXML($response_str);
    if ($this->checkResponse()) {
      kdpm('success');
      return $this->xml;
    }
  }

  /**
   * Test function to get xml string.
   */
  public function xmlOutput() {
    return $this->xml->saveXML();
  }

  /**
   * Prepare document header.
   */
  protected function prepareXmlHeader(DOMElement $header) {
    // Action element.
    $this->addXmlElementNs($header, 'a', 'a:Action', self::ACTION_BASE . $this->action, [
      's:mustUnderstand' => '1',
    ]);

    // Guid element.
    $this->addXmlElementNs($header, 'a', 'a:MessageID', $this->docGuid);

    // Reply-to element.
    $element = $this->addXmlElementNs($header, 'a', 'a:ReplyTo');
    $this->addXmlElementNs($element, 'a', 'a:Address', self::REPLY_TO);

    // To element.
    $this->addXmlElementNs($header, 'a', 'a:To', $this->url, [
      's:mustUnderstand' => '1',
    ]);

    // Security element.
    $this->securityHeader = $this->addXmlElementNs($header, 'o', 'o:Security', NULL, [
      's:mustUnderstand' => '1',
    ]);

    // Timestamp element.
    $this->signatureElements['_0'] = $this->addXmlElementNS($this->securityHeader, 'u', 'u:Timestamp', NULL, [
      'u:Id' => '_0',
    ]);

    // For testing, use ts of 1480082738.764 as an argument.
    $times = $this->getTimestamp();
    $this->addXmlElementNS($this->signatureElements['_0'], 'u', 'u:Created', $times[0]);
    $this->addXmlElementNS($this->signatureElements['_0'], 'u', 'u:Expires', $times[1]);

    // *** Inject security token ***.
    $data = [
      'certPath' => $this->certPath,
      'pkPath' => $this->pkPath,
    ];

    $this->agivSecurityToken->injectToken($this->securityHeader, $this->xml);
  }

  /**
   * Prepare document body.
   */
  protected function prepareXmlBody(DOMElement $body) {
    $element = $this->xml->createElementNS(self::XMLNS_DEFAULT, $this->action);
    $body->appendChild($element);
  }

  /**
   * Sign XML document.
   */
  protected function signXml() {
    $params = [
      'xml' => $this->xml,
      'signatureElements' => $this->signatureElements,
      'canonicalMethod' => AgivSTSSignature::EXC_C14N,
      'pkPath' => $this->pkPath,
    ];

    $sigObject = new AgivSTSSignature($params);

    $reference = $this->agivSecurityToken->getReference();
    $importedReference = $this->xml->importNode($reference, TRUE);

    $secret = $this->agivSecurityToken->getBinarySecret();

    $sigObject->signDocument($this->securityHeader, $importedReference, AgivSTSSignature::HMAC_SHA1, ['secret' => $secret]);
  }

}
