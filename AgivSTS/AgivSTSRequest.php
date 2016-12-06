<?php

namespace AgivSTS;

use DOMDocument;
use DOMElement;
use DOMXpath;
use AgivSTS\Exception\AgivException;

/**
 * Provides methods to build Agiv security token request.
 */
class AgivSTSRequest extends ServiceDocument {

  /**
   * Class constants.
   */

  // Defaults.
  const CONSTRUCTOR_DEFAULTS = [
    'passphrase' => '',
    'action' => 'Issue',
    'realm' => 'urn:agiv.be/gipod',
  ];

  // Header constants.
  const ACTION_BASE = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/';
  const REPLY_TO = 'http://www.w3.org/2005/08/addressing/anonymous';

  // Body constants.
  const REQUEST_TYPE_BASE = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/';

  /**
   * Class properties.
   */

  // Certificate string.
  protected $certPath;

  // Private key path.
  protected $pkPath;

  // Passphrase.
  protected $passphrase;

  // Action performed.
  protected $action;

  // Called URL.
  protected $url;

  // Request realm.
  protected $realm;

  // Document guid.
  protected $docGuid;

  // Document security header element.
  protected $securityHeader;

  // Signature elements.
  protected $signatureElements;

  /**
   * Object constructor.
   */
  public function __construct($data) {
    // Apply defaults.
    foreach (self::CONSTRUCTOR_DEFAULTS as $key => $value) {
      if (is_null($data[$key])) {
        $data[$key] = $value;
      }
    }

    // Set object variables.
    parent::__construct($data);

    // Check if all required values are provided.
    $this->validateVariables();

    // Generate document guid.
    $this->docGuid = self::generateGuid();

    // Prepare document structure.
    $this->xml = new DOMDocument();
    $this->prepareXml();
    $this->signXml();
  }

  /**
   * Validate object variables.
   */
  protected function validateVariables() {
    $missing = [];
    foreach (['url', 'action', 'realm', 'certPath', 'pkPath'] as $variable_name) {
      if (empty($this->{$variable_name})) {
        $missing[] = $variable_name;
      }
    }

    if (!empty($missing)) {
      throw new AgivException('AgivSTSRequest object variables missing: ' . implode(', ', $missing));
    }
  }

  /**
   * Prepare XML header.
   */
  protected function prepareXmlHeader(DOMElement $header) {
    $xml = &$this->xml;

    // Action element.
    $this->addXmlElementNs($header, 'a', 'a:Action', self::ACTION_BASE . $this->action, [
      's:mustUnderstand' => '1',
    ]);

    // Guid element.
    $this->addXmlElementNs($header, 'a', 'a:MessageID', $this->docGuid);

    // Reply-to element.
    $element = $this->addXmlElementNs($header, 'a', 'a:ReplyTo');
    $this->addXmlElementNs($element, 'a', 'a:Address', self::REPLY_TO);

    // Security element.
    $this->securityHeader = $this->addXmlElementNs($header, 'o', 'o:Security', NULL, [
      's:mustUnderstand' => '1',
    ]);

    // Timestamp element.
    $this->signatureElements['_0'] = $this->addXmlElementNS($this->securityHeader, 'u', 'u:Timestamp', NULL, [
      'u:Id' => '_0',
    ]);
    $times = $this->getTimestamp();
    $this->addXmlElementNS($this->signatureElements['_0'], 'u', 'u:Created', $times[0]);
    $this->addXmlElementNS($this->signatureElements['_0'], 'u', 'u:Expires', $times[1]);

    // To element.
    $this->signatureElements['_1'] = $this->addXmlBeforeNs($header, $this->securityHeader, 'a', 'a:To', $this->url, [
      's:mustUnderstand' => '1',
      'u:Id' => '_1',
    ]);

  }

  /**
   * Prepare XML body.
   */
  protected function prepareXmlBody(DOMElement $body) {
    $request_element = $this->addXmlElementNs($body, 'trust', 'trust:RequestSecurityToken', NULL);

    $element = $this->addXmlElementNs($request_element, 'wsp', 'wsp:AppliesTo', NULL);
    $element = $this->addXmlElementNs($element, 'wsa', 'wsa:EndpointReference', NULL);
    $this->addXmlElementNs($element, 'wsa', 'wsa:Address', $this->realm);

    $element = $this->addXmlElementNs($request_element, 'trust', 'trust:RequestType', self::REQUEST_TYPE_BASE . $this->action);
  }

  /**
   * Sign XML document.
   */
  protected function signXml() {
    $params = [
      'xml' => $this->xml,
      'signatureElements' => $this->signatureElements,
      'canonicalMethod' => AgivSTSSignature::EXC_C14N,
      'certPath' => $this->certPath,
      'pkPath' => $this->pkPath,
      'passphrase' => $this->passphrase,
    ];

    $sigObject = new AgivSTSSignature($params);
    $sigObject->signDocument($this->securityHeader);

  }

}
