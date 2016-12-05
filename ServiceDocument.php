<?php

namespace AgivSTS;

require_once __DIR__ . '/AgivSTSBase.php';

use DOMElement;

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
