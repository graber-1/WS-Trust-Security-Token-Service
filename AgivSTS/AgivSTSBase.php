<?php

namespace AgivSTS;

use DOMXpath;
use DOMNode;
use AgivSTS\Exception\AgivException;

/**
 * Base class for Agiv STS library.
 */
abstract class AgivSTSBase {

  // XML namespaces used in STS related documents.
  const XMLNS = [
    's' => 'http://www.w3.org/2003/05/soap-envelope',
    'a' => 'http://www.w3.org/2005/08/addressing',
    'u' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
    'o' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
    'trust' => 'http://docs.oasis-open.org/ws-sx/ws-trust/200512',
    'wsp' => 'http://schemas.xmlsoap.org/ws/2004/09/policy',
    'wsa' => 'http://www.w3.org/2005/08/addressing',
    'b' => 'http://www.agiv.be/Gipod/2010/06',
    'i' => 'http://www.w3.org/2001/XMLSchema-instance',
    'c' => 'http://schemas.microsoft.com/2003/10/Serialization/Arrays',
    '' => 'http://www.w3.org/2000/09/xmldsig#',
  ];

  /**
   * Xml DOMDocument Object.
   *
   * @var DOMDocument
   */
  protected $xml;

  /**
   * General constructor.
   *
   * Assigns argument array values to created object properties.
   *
   * @param array $data
   *   Associative array of object property values.
   */
  public function __construct(array $data) {
    // Set object properties.
    foreach ($this as $property => $value) {
      if (!empty($data[$property])) {
        $this->$property = $data[$property];
      }
    }
  }

  /**
   * Output xml as a string.
   *
   * @return string
   *   The xml string.
   */
  public function xmlOutput() {
    return $this->xml->saveXML();
  }

  /**
   * Prepare XML element.
   *
   * @param string $name
   *   The name of the element.
   * @param string $content
   *   The value of the element.
   * @param array $attributes
   *   Associative array of element attributes.
   *
   * @return \DOMElement
   *   The created element.
   */
  protected function prepareXmlElement($name, $content = NULL, array $attributes = []) {
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
   *
   * @param string $namespace
   *   Namespace prefix if defined in self:XMLNS or URI.
   * @param string $name
   *   The name of the element.
   * @param string $content
   *   The value of the element.
   * @param array $attributes
   *   Associative array of element attributes.
   * @param array $namespaces
   *   Array of namespace prefixes or URIs.
   *
   * @return \DOMElement
   *   The created element.
   */
  protected function prepareXmlElementNs($namespace, $name, $content = NULL, array $attributes = [], array $namespaces = []) {
    $xml = &$this->xml;
    if (array_key_exists($namespace, self::XMLNS)) {
      $element = $xml->createElementNS(self::XMLNS[$namespace], $name, $content);
    }
    elseif (substr($namespace, 0, 4) == 'http') {
      $element = $xml->createElementNS($namespace, $name, $content);
    }
    else {
      throw new AgivException(sprintf('Namespace "%s" is not defined.', $namespace));
    }

    // Add attributes.
    foreach ($attributes as $attribute => $value) {
      if (($pos = strpos($attribute, ':')) !== FALSE) {
        $namespace = substr($attribute, 0, $pos);
        if (array_key_exists($namespace, self::XMLNS)) {
          $element->setAttributeNS(self::XMLNS[$namespace], $attribute, $value);
        }
        else {
          throw new AgivException(sprintf('Namespace "%s" is not defined.', $namespace));
        }
      }
      else {
        $element->setAttribute($attribute, $value);
      }
    }

    // Add additional namespaces if present.
    foreach ($namespaces as $namespace) {
      if (array_key_exists($namespace, self::XMLNS)) {
        $ns_name = 'xmlns';
        if (!empty($namespace)) {
          $ns_name .= ':' . $namespace;
        }
        $element->setAttributeNS('http://www.w3.org/2000/xmlns/', $ns_name, self::XMLNS[$namespace]);
      }
      else {
        throw new AgivException(sprintf('Namespace "%s" is not defined.', $namespace));
      }
    }

    return $element;
  }

  /**
   * Helper function.
   *
   * Creates an xml element with optional attributes and content and append it.
   * For the rest of the parameters @see prepereXmlElement.
   *
   * @param \DOMNode $parent
   *   The element to which the created element should be appended.
   *
   * @return \DOMNode
   *   The created element.
   */
  protected function addXmlElement(DOMNode $parent, $name, $content = NULL, $attributes = []) {
    $element = $this->prepareXmlElement($name, $content, $attributes);
    $parent->appendChild($element);
    return $element;
  }

  /**
   * Helper function.
   *
   * Creates namespaced xml element with optional
   * attributes and content and appends it to $parent.
   * For the rest of the parameters @see prepereXmlElementNs.
   *
   * @param \DOMNode $parent
   *   The element to which the created element should be appended.
   *
   * @return \DOMNode
   *   The created element.
   */
  protected function addXmlElementNs(DOMNode $parent, $namespace, $name, $content = NULL, $attributes = [], $namespaces = []) {
    $element = $this->prepareXmlElementNs($namespace, $name, $content, $attributes, $namespaces);
    $parent->appendChild($element);
    return $element;
  }

  /**
   * Helper function.
   *
   * Creates xml element with optional
   * attributes and content and adds it before the specified element.
   * For the rest of the parameters @see addXmlElement.
   *
   * @param \DOMNode $next
   *   The node before which the new element will be inserted.
   *
   * @return \DOMNode
   *   The created element.
   */
  protected function addXmlBefore(DOMNode $parent, DOMNode $next, $name, $content = NULL, $attributes = []) {
    $element = $this->prepareXmlElement($name, $content, $attributes);
    $parent->insertBefore($element, $next);
    return $element;
  }

  /**
   * Helper function.
   *
   * Creates namespaced xml element with optional
   * attributes and content and add it before the specified element.
   * For the rest of the parameters @see addXmlElementNs.
   *
   * @param \DOMNode $next
   *   The node before which the new element will be inserted.
   *
   * @return \DOMNode
   *   The created element.
   */
  protected function addXmlBeforeNs(DOMNode $parent, DOMNode $next, $namespace, $name, $content = NULL, array $attributes = []) {
    $element = $this->prepareXmlElementNs($namespace, $name, $content, $attributes);
    $parent->insertBefore($element, $next);
    return $element;
  }

  /**
   * Get datetime in correct format.
   *
   * @param int $microtime
   *   Time to convert.
   * @param int $offset
   *   Second time offset.
   *
   * @return array
   *   Array of 2 formatted date strings.
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
   *
   * @param string $prefix
   *   String to prepend to guid.
   * @param string $suffix
   *   String to append to guid.
   *
   * @return string
   *   The generated guid.
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
   *
   * @return bool
   *   TRUE if the output has no errors, throws an exception otherwise.
   */
  protected function checkResponse() {
    $fault = $this->xml->getElementsByTagNameNS(self::XMLNS['s'], 'Fault')->item(0);
    if (!empty($fault)) {
      $error_data = [
        'reason' => 's:Reason/s:Text',
        'code' => 's:Code/s:Value',
        'subcode' => 's:Code/s:Subcode/s:Value',
        'tag' => 's:Detail/tp:FaultDetail/tp:Messages/tp:FaultMessage/tp:Tag',
      ];

      $xpath = new DOMXpath($this->xml);
      $xpath->registerNameSpace('tp', 'http://www.agiv.be/ErrorHandling/2010/04');
      foreach ($error_data as $key => $query) {
        $result = $xpath->query($query, $fault);
        if ($result->length) {
          $error_data[$key] = (string) $result->item(0)->nodeValue;
        }
        else {
          $error_data[$key] = 'not provided';
        }
      }
      $error_data = ['class' => get_class($this)] + $error_data;
      throw new AgivException(vsprintf('%s error: %s Code: %s, subcode: %s, tag: %s.', $error_data), $error_data);
    }
    return TRUE;
  }

}
