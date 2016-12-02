<?php

namespace AgivSTS;

use DOMDocument;
use DOMElement;
use DOMXpath;

/**
 * Base class for Agiv STS library.
 */
abstract class AgivSTSBase {

  // Namespaces.
  const XMLNS = [
    's' => 'http://www.w3.org/2003/05/soap-envelope',
    'a' => 'http://www.w3.org/2005/08/addressing',
    'u' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
    'o' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
    'trust' => 'http://docs.oasis-open.org/ws-sx/ws-trust/200512',
    'wsp' => 'http://schemas.xmlsoap.org/ws/2004/09/policy',
    'wsa' => 'http://www.w3.org/2005/08/addressing',
    '' => 'http://www.w3.org/2000/09/xmldsig#',
  ];

  // Xml DOMDocument Object.
  protected $xml;

  /**
   * General constructor.
   */
  public function __construct($data) {
    // Set object properties.
    foreach ($this as $property => $value) {
      if (!empty($data[$property])) {
        $this->$property = $data[$property];
      }
    }
  }

  /**
   * Output xml as a string.
   */
  public function xmlOutput() {
    return $this->xml->saveXML();
  }

  /**
   * Prepare element.
   */
  protected function prepareXmlElement($name, $content = NULL, $attributes = []) {
    $xml = &$this->xml;
    $element = $xml->createElement($name, $content);
    foreach ($attributes as $attribute => $value) {
      $namespaces = [];
      $element->setAttribute($attribute, $value);
    }
    return $element;
  }

  /**
   * Prepare namespaced element.
   */
  protected function prepareXmlElementNs($namespace, $name, $content = NULL, $attributes = [], $namespaces = []) {
    $xml = &$this->xml;

    if (self::XMLNS[$namespace] !== NULL) {
      $element = $xml->createElementNS(self::XMLNS[$namespace], $name, $content);
    }
    else {
      throw new \Exception(sprintf('Namespace "%s" is not defined.', $namespace));
    }

    // Add attributes.
    foreach ($attributes as $attribute => $value) {
      if (($pos = strpos($attribute, ':')) !== FALSE) {
        $namespace = substr($attribute, 0, $pos);
        if (self::XMLNS[$namespace] !== NULL) {
          $element->setAttributeNS(self::XMLNS[$namespace], $attribute, $value);
        }
        else {
          throw new \Exception(sprintf('Namespace "%s" is not defined.', $namespace));
        }
      }
      else {
        $element->setAttribute($attribute, $value);
      }
    }

    // Add additional namespaces if present.
    foreach ($namespaces as $namespace) {
      if (self::XMLNS[$namespace] !== NULL) {
        $ns_name = 'xmlns';
        if (!empty($namespace)) {
          $ns_name .= ':' . $namespace;
        }
        $element->setAttributeNS('http://www.w3.org/2000/xmlns/', $ns_name, self::XMLNS[$namespace]);
      }
      else {
        throw new \Exception(sprintf('Namespace "%s" is not defined.', $namespace));
      }
    }

    return $element;
  }

  /**
   * Helper function to create xml element with optional attributes and content and append it.
   */
  protected function addXmlElement($parent, $name, $content = NULL, $attributes = []) {
    $element = $this->prepareXmlElement($name, $content, $attributes);
    $parent->appendChild($element);
    return $element;
  }

  /**
   * Helper function to create namespaced xml element with optional attributes and content and append it.
   */
  protected function addXmlElementNs($parent, $namespace, $name, $content = NULL, $attributes = [], $namespaces = []) {
    $element = $this->prepareXmlElementNs($namespace, $name, $content, $attributes, $namespaces);
    $parent->appendChild($element);
    return $element;
  }

  /**
   * Helper function to create xml element with optional attributes and content and add it before the specified element.
   */
  protected function addXmlBefore($parent, $next, $name, $content = NULL, $attributes = []) {
    $element = $this->prepareXmlElement($name, $content, $attributes);
    $parent->insertBefore($element, $next);
    return $element;
  }

  /**
   * Helper function to create namespaced xml element with optional attributes and content and add it before the specified element.
   */
  protected function addXmlBeforeNs($parent, $next, $namespace, $name, $content = NULL, $attributes = []) {
    $element = $this->prepareXmlElementNs($namespace, $name, $content, $attributes);
    $parent->insertBefore($element, $next);
    return $element;
  }

  /**
   * Get time in correct format.
   */
  protected function getTimestamp($microtime = NULL, $offset = 300) {
    if (!isset($microtime)) {
      $microtime = microtime(TRUE);
    }
    $microtime = (string) $microtime;
    $parts = explode('.', $microtime);
    if (strlen($parts[1]) > 3) {
      $parts[1] = substr($parts[1], 0, 3);
    }
    while (strlen($parts[1]) < 3) {
      $parts[1] .= '0';
    }

    $output = [];
    $output[] = gmdate('Y-m-d\TH:i:s', $parts[0]) . '.' . $parts[1] . 'Z';
    $output[] = gmdate('Y-m-d\TH:i:s', ($parts[0] + $offset)) . '.' . $parts[1] . 'Z';

    return $output;
  }

  /**
   * Helper function to generate guid.
   */
  public static function generateGuid($prefix = 'urn:uuid:', $suffix = '') {
    $uuid = md5(uniqid(mt_rand(), TRUE));

    $guid = '';
    if (!empty($prefix)) {
      $guid .= $prefix;
    }

    $guid .= substr($uuid, 0, 8) . "-" .
    substr($uuid, 8, 4) . "-" .
    substr($uuid, 12, 4) . "-" .
    substr($uuid, 16, 4) . "-" .
    substr($uuid, 20, 12);

    if (!empty($suffix)) {
      $guid .= $suffix;
    }

    return $guid;
  }

  /**
   * Parse xml response: error handling.
   */
  protected function checkResponse() {
    $fault = $this->xml->getElementsByTagNameNS(self::XMLNS['s'], 'Fault')->item(0);
    if (!empty($fault)) {
      $error_data = [
        'reason' => 's:Reason/s:Text',
        'code' => 's:Code/s:Value',
        'subcode' => 's:Code/s:Subcode/s:Value',
      ];

      $xpath = new DOMXpath($this->xml);
      foreach ($error_data as $key => $query) {
        $result = $xpath->query($query, $fault);
        if ($result->length) {
          $error_data[$key] = (string) $result->item(0)->nodeValue;
        }
        else {
          $error_data[$key] = 'not provided';
        }
      }
      array_unshift($error_data, get_class($this));
      throw new \Exception(vsprintf('%s error: %s Code: %s, subcode: %s.', $error_data));
    }
    return TRUE;
  }

}

/**
 * Base class for service document.
 */
abstract class ServiceDocument extends AgivSTSBase {

  /**
   * Prepare base XML elements.
   */
  protected function prepareXml($namespace = 's', $namespaces = ['a', 'u']) {
    $xml = &$this->xml;

    // Root element.
    $root = $this->addXmlElementNs($xml, $namespace, $namespace . ':Envelope', NULL, [], $namespaces);

    // Header element.
    $this->header = $this->addXmlElementNs($root, $namespace, $namespace . ':Header');
    $this->prepareXmlHeader($this->header);

    // Body element.
    $body_element = $this->addXmlElementNs($root, $namespace, $namespace . ':Body');
    $this->prepareXmlBody($body_element);
  }

  /**
   * Prepare document header.
   */
  abstract protected function prepareXmlHeader(DOMElement $header);

  /**
   * Prepare document body.
   */
  abstract protected function prepareXmlBody(DOMElement $body);

}
