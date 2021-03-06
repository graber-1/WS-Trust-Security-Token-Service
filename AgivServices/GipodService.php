<?php

namespace AgivServices;

use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXpath;
use AgivSTS\ServiceDocument;
use AgivSTS\AgivSecurityToken;
use AgivSTS\AgivSTSSignature;
use AgivSTS\Exception\AgivException;
use GuzzleHttp\Exception\GuzzleException;

/**
 * Class for accessing Gipod webAPI.
 */
class GipodService extends ServiceDocument {

  const CONSTRUCTOR_DEFAULTS = [
    'action' => 'GetListLocatieHinder',
    'url' => 'https://gipod.agiv.be/Webservice/GipodService.svc/wsfed',
    'realm' => 'urn:agiv.be/gipod',
  ];

  const ACTION_BASE = 'http://www.agiv.be/Gipod/2010/06/service/IGipodService/';
  const REPLY_TO = 'http://www.w3.org/2005/08/addressing/anonymous';

  const XMLNS_DEFAULT = 'http://www.agiv.be/Gipod/2010/06/service';

  // Parameter namespaces: first value is parent namespace,
  // second is child element namespace. If there is no parent,
  // first value applies to the value element.
  const PARAM_NAMESPACES = [
    'WerkopdrachtStatusIds' => ['b', 'c'],
    'ManifestatieStatusIds' => ['b', 'c'],
    'AanwezigheidOpenbaarDomeinTypes' => ['b', 'b'],
    'StatusIds' => ['b', 'c'],
  ];

  // Parameter types: Sometimes parameter
  // types are not int or string, but special types.
  const PARAM_TYPES = [
    'AanwezigheidOpenbaarDomeinTypes' => 'AanwezigheidOpenbaarDomeinType',
  ];

  // Action result namespace.
  const RESULT_XMLNS = 'http://www.agiv.be/Gipod/2010/06/service';

  // Result Array element names for result parsing.
  const RESULT_ARRAY_ELEMENTS = ['EnumeratieElement'];

  // Action result paths.
  // For a list of methods, refer to:
  // https://gipod.agiv.be/Webservice/help/ME-GipodService.htm.
  const ACTION_PATHS = [
    'GetListLocatieHinder' => ['data' => 'b:HinderLocatieElementen/b:EnumeratieElement'],
    'ListHinder' => [
      'nextRecord' => 'b:NextRecord',
      'data' => 'b:InnameHinder/b:InnameHinderItem',
    ],
  ];

  // Not found error tags.
  const NOT_FOUND_TAGS = [
    'WerkopdrachtNotFound',
  ];

  /**
   * Object settings.
   *
   * @var array
   */
  protected $settings;
  protected $url;
  protected $action;

  /**
   * Request parameters.
   *
   * @var array
   */
  protected $parameters;

  protected $docGuid;

  /**
   * Security token object.
   *
   * @var \AgivSTS\AgivSecurityToken
   */
  protected $agivSecurityToken;

  /**
   * Preconfigured HTTP client (Guzzle).
   *
   * @var \GuzzleHttp\Client
   */
  protected $httpClient;

  protected $securityHeader;
  protected $signatureElements;

  /**
   * Private key path.
   *
   * @var string
   */
  protected $pkPath;

  /**
   * Certificate path.
   *
   * @var string
   */
  protected $certPath;

  /**
   * {@inheritdoc}
   */
  public function __construct($data = []) {
    // Apply defaults.
    foreach (self::CONSTRUCTOR_DEFAULTS as $key => $value) {
      if (!isset($data[$key])) {
        $data[$key] = $value;
      }
    }

    parent::__construct($data);
  }

  /**
   * Validate object variables.
   */
  protected function validateVariables() {
    $missing = [];
    foreach (['action', 'url', 'agivSecurityToken', 'httpClient'] as $variable_name) {
      if (empty($this->$variable_name)) {
        $missing[] = $variable_name;
      }
    }

    if (!empty($missing)) {
      throw new AgivException('Gipod object variables missing: ' . implode(', ', $missing));
    }

    if (isset($this->parameters) && !is_array($this->parameters)) {
      throw new AgivException(sprintf('Gipod method parameters must be an array, %s given.', gettype($this->parameters)));
    }

  }

  /**
   * Gipod request builder.
   */
  public function buildRequest() {
    // Check if all required values are provided.
    $this->validateVariables();

    // Load security token.
    $this->agivSecurityToken->load('gipod');

    // Generate document guid.
    $this->docGuid = self::generateGuid();

    $this->xml = new DOMDocument();
    $this->prepareXml();
    $this->signXml();
  }

  /**
   * Execute request.
   *
   * @param string $action
   *   Method to call.
   * @param array $parameters
   *   Array of method parameters.
   * @param bool $bypass_paths
   *   If set to TRUE, predefined data paths will be ignored
   *   and entire result structure will be returned.
   * @param int $try
   *   Internal use only.
   *
   * @return mixed
   *   Array of returned data or XML string if data couldn't be parsed.
   */
  public function call($action = FALSE, array $parameters = array(), $bypass_paths = FALSE, $try = 0) {
    if ($action) {
      $this->action = $action;
    }
    $this->parameters = $parameters;

    $this->buildRequest();

    $options = [
      'headers' => [
        'Content-Type' => 'application/soap+xml; charset=utf-8',
      ],
      'body' => $this->xmlOutput(),
      'verify' => FALSE,
    ];
    try {
      $response = $this->httpClient->post($this->url, $options);
      $response_str = (string) $response->getBody();
    }
    catch (GuzzleException $e) {
      $response_str = (string) $e->getResponse()->getBody();
    }
    catch (\Exception $e) {
      throw new AgivException($e->getMessage(), [
        'class' => get_class($this),
        'method' => $this->action,
        'reason' => 'Possible: gipod server down or wrong action name.',
        'code' => 500,
      ]);
    }

    $this->xml->loadXML($response_str);

    try {
      $this->checkResponse();
      return $this->processOutput($bypass_paths);
    }
    catch (AgivException $e) {
      if (isset($e->faultData['tag']) && in_array($e->faultData['tag'], self::NOT_FOUND_TAGS)) {
        throw $e;
      }
      $ntries = isset($this->settings['max_service_attempts']) ? $this->settings['max_service_attempts'] : 1;

      if ($try < $ntries) {
        $try++;
        // Reload token from STS.
        $this->agivSecurityToken->load('gipod', TRUE);
        $this->call($action, $parameters, $bypass_paths, $try);
      }
      else {
        $e->faultData['attempts'] = $try;
        throw $e;
      }
    }
  }

  /**
   * Implements __call magic method to call gipod service method.
   *
   * @param string $name
   *   Method to call.
   * @param array $arguments
   *   Arguments of the caller.
   *
   * @return mixed
   *   Return of the call method. @see \AgivServices\GipodService::call.
   */
  public function __call($name, array $arguments = []) {
    if (!isset($arguments[0])) {
      $arguments[0] = [];
    }
    if (!isset($arguments[1])) {
      $arguments[1] = FALSE;
    }
    return $this->call($name, $arguments[0], $arguments[1]);
  }

  /**
   * Test function to get the current xml string.
   */
  public function xmlOutput() {
    return $this->xml->saveXML();
  }

  /**
   * {@inheritdoc}
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
    $times = $this->getTimestamp();
    $this->addXmlElementNS($this->signatureElements['_0'], 'u', 'u:Created', $times[0]);
    $this->addXmlElementNS($this->signatureElements['_0'], 'u', 'u:Expires', $times[1]);

    // *** Inject security token ***.
    $this->agivSecurityToken->injectToken($this->securityHeader, $this->xml);
  }

  /**
   * {@inheritdoc}
   */
  protected function prepareXmlBody(DOMElement $body) {
    $element = $this->xml->createElementNS(self::XMLNS_DEFAULT, $this->action);
    $body->appendChild($element);
    $param_ns = self::PARAM_NAMESPACES;

    if (!empty($this->parameters) && is_array($this->parameters)) {

      $request = $this->addXmlElementNS($element, self::XMLNS_DEFAULT, 'request', NULL, [], ['b', 'i']);
      foreach ($this->parameters as $name => $value) {
        if (isset($param_ns[$name])) {
          $namespaces = $param_ns[$name];
        }
        else {
          $namespaces = ['b', 'b'];
        }

        if (is_array($value)) {
          if (array_key_exists($name, self::PARAM_TYPES)) {
            $child_name = $namespaces[1] . ':' . self::PARAM_TYPES[$name];
          }
          else {
            $child_name = $namespaces[1] . ':int';
          }

          if (empty($namespaces[1]) || $namespaces[1] == 'b') {
            $parent_ns = [];
          }
          else {
            $parent_ns = [$namespaces[1]];
          }

          $arrayElement = $this->addXmlElementNS(
            $request,
            $namespaces[0],
            $namespaces[0] . ':' . $name,
            NULL,
            empty($value) ? ['i:nil' => 'true'] : [],
            $parent_ns
          );
          foreach ($value as $name => $item) {
            if (is_numeric($name)) {
              $this->addXmlElementNS($arrayElement, $namespaces[1], $child_name, $item);
            }
            else {
              $this->addXmlElementNS($arrayElement, $namespaces[1], $name, $item);
            }
          }
        }
        else {
          $this->addXmlElementNS(
            $request,
            $namespaces[0],
            $namespaces[0] . ':' . $name,
            $value,
            empty($value) ? ['i:nil' => 'true'] : []
          );
        }
      }
    }
  }

  /**
   * Sign XML document.
   */
  protected function signXml() {
    $params = [
      'xml' => $this->xml,
      'signatureElements' => $this->signatureElements,
      'canonicalMethod' => AgivSTSSignature::EXC_C14N,
    ];

    $sigObject = new AgivSTSSignature($params);

    $reference = $this->agivSecurityToken->getReference();
    $importedReference = $this->xml->importNode($reference, TRUE);

    $secret = $this->agivSecurityToken->getBinarySecret();

    $sigObject->signDocument($this->securityHeader, $importedReference, AgivSTSSignature::HMAC_SHA1, ['secret' => $secret]);
  }

  /**
   * Process output data for Gipod methods.
   *
   * @param bool $bypass_paths
   *   Should action paths defined as the class
   *   constant be bypassed and the entire data object returned?
   *
   * @return mixed
   *   Data array or XML string if failed to find the result element.
   */
  private function processOutput($bypass_paths = FALSE) {
    $output = [];

    $resultElement = $this->xml->getElementsByTagNameNS(self::RESULT_XMLNS, $this->action . 'Result')->item(0);
    if ($resultElement) {
      if (array_key_exists($this->action, self::ACTION_PATHS) && !$bypass_paths) {
        $xpath = new DOMXPath($this->xml);
        foreach (self::ACTION_PATHS[$this->action] as $key => $query) {
          $result = $xpath->query($query, $resultElement);
          if ($result->length) {
            for ($i = 0; $i < $result->length; $i++) {
              $node = $result->item($i);
              $output[$key][$i] = $this->getNodeValue($node);
            }
          }
        }
      }
      else {
        $output = $this->getNodeValue($resultElement);
      }
    }
    else {
      $output = $this->xml->saveXML();
    }
    return $output;
  }

  /**
   * Helper function to recursively return values of DOMNode and its children.
   *
   * @param \DOMNode $node
   *   The node.
   *
   * @return mixed
   *   The value of the node or array of values if the node had children.
   */
  protected function getNodeValue(DOMNode $node) {

    $childNodes = [];
    for ($i = 0; $i < $node->childNodes->length; $i++) {
      if ($node->childNodes->item($i)->nodeType === XML_ELEMENT_NODE) {
        $childNodes[] = $node->childNodes->item($i);
      }
    }

    if (!empty($childNodes)) {
      foreach ($childNodes as $childNode) {
        if (in_array($childNode->localName, self::RESULT_ARRAY_ELEMENTS)) {
          $output[] = $this->getNodeValue($childNode);
        }
        else {
          // Also support returning arrays.
          if (!isset($namecount[$childNode->localName])) {
            $namecount[$childNode->localName] = 1;
          }
          else {
            $namecount[$childNode->localName]++;
          }

          if ($namecount[$childNode->localName] == 2) {
            $output[$childNode->localName] = [$output[$childNode->localName]];
          }
          if ($namecount[$childNode->localName] == 1) {
            $output[$childNode->localName] = $this->getNodeValue($childNode);
          }
          else {
            $output[$childNode->localName][] = $this->getNodeValue($childNode);
          }
        }
      }
    }
    else {
      $output = $node->nodeValue;
    }

    if (isset($output)) {
      return $output;
    }
    return NULL;
  }

}
