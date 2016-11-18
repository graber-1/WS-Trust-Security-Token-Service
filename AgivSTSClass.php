<?php

namespace AgivSTS;

require_once __DIR__ . '/../../robrichards/xmlseclibs/xmlseclibs.php';
use DOMDocument;
use DOMXpath;

/**
 * @file
 * Contains main class fot Gipod integration.
 */

/**
 * Provides methods to retrieve Agiv security token.
 */
class AgivSTS {

  /**
   * Certificate string.
   */
  protected $certificate;

  /**
   * Xml DOMDocument Object.
   */
  protected $xml;

  /**
   * Object constructor.
   */
  public function __construct($data) {
    if (!empty($data['certificate'])) {
      $this->setCertificate($data['certificate']);
    }
    if (!empty($data['xml'])) {
      $this->xml = $data['xml'];
    }
    else {
      // Prepare document structure.
      $this->xml = new DOMDocument();
      $this->prepareXml();
    }
    if (!empty($data['xml_string'])) {
      $this->doc->load($data['xml_string']);
    }
  }

  /**
   * Set certificate.
   */
  public function setCertificate($certificate) {
    $this->certificate = $certificate;
  }

  /**
   * Prepare XML.
   */
  protected function prepareXml() {
    $root = $this->xml->createElement('s:Envelope');
    $root->setAttribute('xmlns:s', 'http://www.w3.org/2003/05/soap-envelope');
    $root->setAttribute('xmlns:a', 'http://www.w3.org/2005/08/addressing');
    $root->setAttribute('xmlns:u', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
    $string = $this->xml->saveXML();

    kdpm($string);

  }

}
