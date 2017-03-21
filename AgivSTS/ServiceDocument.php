<?php

namespace AgivSTS;

use DOMElement;

/**
 * Base class for service document.
 */
abstract class ServiceDocument extends AgivSTSBase {

  /**
   * Prepare base XML elements.
   *
   * Prepares SOAP envelope and header and body elements.
   *
   * @var string $namespace
   *   Main document namespace.
   * @var array $namespaces
   *   Array of additional document namespaces.
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
   *
   * @var \DOMElement $header
   *   The header element.
   */
  abstract protected function prepareXmlHeader(DOMElement $header);

  /**
   * Prepare document body.
   *
   * @var \DOMElement $body
   *   The body element.
   */
  abstract protected function prepareXmlBody(DOMElement $body);

}
