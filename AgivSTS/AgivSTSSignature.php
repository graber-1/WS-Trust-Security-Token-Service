<?php

namespace AgivSTS;

use AgivSTS\Exception\AgivException;

/**
 * Class for signing XML documents for AGIV service.
 *
 * Based on robrichards/xmlseclibs.
 */
class AgivSTSSignature extends AgivSTSBase {

  /*
   * Class constants.
   */

  // Algorithms.
  const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
  const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
  const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
  const SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';
  const RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160';
  const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
  const HMAC_SHA1 = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';

  // Canonicalization methods.
  const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
  const C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
  const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  const EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

  const TOKEN_VALUE_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
  const TOKEN_ENCODING_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

  /**
   * Signature elements.
   *
   * @var array
   *   An array of DOMElements
   */
  protected $signatureElements;

  /**
   * Canonization method.
   *
   * @var string
   */
  protected $canonicalMethod;

  /**
   * Certificate path.
   *
   * @var string
   */
  protected $certPath;

  /**
   * Private key path.
   *
   * @var string
   */
  protected $pkPath;

  /**
   * Passphrase.
   *
   * @var string
   */
  protected $passphrase;

  /**
   * BinarySecurityToken ID.
   *
   * @var string
   */
  protected $securityTokenId;

  /**
   * Object constructor.
   */
  public function __construct($data) {
    parent::__construct($data);
    $this->securityTokenId = self::generateGuid('uuid-', '-2');
  }

  /**
   * Sign document base function.
   */
  public function signDocument($element, $key_info = FALSE, $method = self::RSA_SHA1, $parameters = array()) {
    // Add certificate.
    if (!empty($this->certPath)) {
      $this->addXmlElementNs($element, 'o', 'o:BinarySecurityToken', $this->getCertificateData($this->certPath), [
        'u:Id' => $this->securityTokenId,
        'ValueType' => self::TOKEN_VALUE_TYPE,
        'EncodingType' => self::TOKEN_ENCODING_TYPE,
      ]);
    }

    // Add signature element.
    $signature = $this->addXmlElementNs($element, '', 'Signature', NULL);

    // Add signed info.
    $signed_info = $this->addXmlElementNs($signature, '', 'SignedInfo', NULL);
    $this->addXmlElementNs($signed_info, '', 'CanonicalizationMethod', NULL, [
      'Algorithm' => self::EXC_C14N,
    ]);
    $this->addXmlElementNs($signed_info, '', 'SignatureMethod', NULL, [
      'Algorithm' => $method,
    ]);

    // References.
    foreach ($this->signatureElements as $id => $signatureElement) {
      $ref_node = $this->addXmlElementNs($signed_info, '', 'Reference', NULL, [
        'URI' => '#' . $id,
      ]);
      $transforms = $this->addXmlElementNs($ref_node, '', 'Transforms');

      $transforms_arr = [];
      $transforms_arr[] = $this->addXmlElementNs($transforms, '', 'Transform', NULL, [
        'Algorithm' => self::EXC_C14N,
      ]);

      $this->addXmlElementNs($ref_node, '', 'DigestMethod', NULL, [
        'Algorithm' => self::SHA1,
      ]);

      $canonicalData = $this->signatureElements[$id]->C14N(TRUE, FALSE);

      $digValue = $this->calculateDigest(self::SHA1, $canonicalData);
      $this->addXmlElementNs($ref_node, '', 'DigestValue', $digValue);
    }

    // Add signature value.
    $this->addXmlElementNs($signature, '', 'SignatureValue', $this->getSignatureValue($signed_info, $method, $parameters));

    // Add security key (certificate) info.
    if (!empty($this->certPath) || $key_info !== FALSE) {
      $keyInfoElement = $this->addXmlElementNs($signature, '', 'KeyInfo');

      if (!empty($this->certPath)) {
        $token_ref = $this->addXmlElementNs($keyInfoElement, 'o', 'o:SecurityTokenReference');
        $this->addXmlElementNs($token_ref, 'o', 'o:Reference', NULL, [
          'URI' => '#' . $this->securityTokenId,
        ]);
      }
      else {
        $keyInfoElement->appendChild($key_info);
      }
    }
  }

  /**
   * Get certificate data.
   */
  protected function getCertificateData($certPath) {
    if ($cert_contents = file_get_contents($certPath)) {
      $data = '';

      $arCert = explode("\n", $cert_contents);
      foreach ($arCert as $curData) {
        if (
          strncmp($curData, '-----BEGIN CERTIFICATE', 22) == 0 ||
          strncmp($curData, '-----END CERTIFICATE', 20) == 0
        ) {
          continue;
        }
        else {
          $data .= trim($curData);
        }
      }
      return $data;
    }
    else {
      throw new AgivException('Can\'t retrieve certificate file contents.');
    }
  }

  /**
   * Calculate digest value.
   *
   * Function from robrichards/xmlseclibs /src/XMLSecurityDSig.php.
   */
  public function calculateDigest($digestAlgorithm, $data) {
    switch ($digestAlgorithm) {
      case self::SHA1:
        $alg = 'sha1';
        break;

      case self::SHA256:
        $alg = 'sha256';
        break;

      case self::SHA384:
        $alg = 'sha384';
        break;

      case self::SHA512:
        $alg = 'sha512';
        break;

      case self::RIPEMD160:
        $alg = 'ripemd160';
        break;

      default:
        throw new AgivException("Cannot calculate digest: Unsupported Algorithm <$digestAlgorithm>");
    }

    return base64_encode(hash($alg, $data, TRUE));
  }

  /**
   * Get signature value.
   */
  protected function getSignatureValue($sigInfoElement, $method, $parameters) {
    $data = $sigInfoElement->C14N(TRUE, FALSE);

    switch ($method) {
      case self::RSA_SHA1:
        $pk_string = file_get_contents($this->pkPath);
        $private_key = openssl_pkey_get_private($pk_string, $this->passphrase);

        if (!openssl_sign($data, $signature, $private_key, OPENSSL_ALGO_SHA1)) {
          throw new AgivException('Failure Signing Data: ' . openssl_error_string() . ' - ' . OPENSSL_ALGO_SHA1);
        }
        openssl_free_key($private_key);
        $signature = base64_encode($signature);
        break;

      case self::HMAC_SHA1:
        if (!isset($parameters['secret'])) {
          $parameters['secret'] = '';
        }
        $parameters['secret'] = base64_decode($parameters['secret']);
        $signature = base64_encode(hash_hmac('sha1', $data, $parameters['secret'], TRUE));
        break;

      default:
        throw new AgivException(sprintf('Failure Signing Data: method %s not supported.', $method));
    }

    return $signature;
  }

  /**
   * Canonicalize node using Exclusive XML Canonicalization.
   *
   * Currently not used, may come in handy when
   * XML DOMDocument is not constructed properly with use of namespaces.
   * May also be faster than C14N method. Leaving for future consideration.
   */
  protected function exclusiveCanonicalization($node, $used_namespaces = []) {

    // Find all possible namespaces in the node.
    $namespaces = [];
    if (($pos = strpos($node->nodeName, ':')) !== FALSE) {
      $namespace = substr($node->nodeName, 0, $pos);
      if (!isset($used_namespaces[$namespace])) {
        $used_namespaces[$namespace] = $namespaces[$namespace] = $namespace;
      }
    }
    else {
      // Append unprefixed namespace if there is no prefix.
      if (!isset($used_namespaces[''])) {
        $used_namespaces[''] = $namespaces[''] = '';
      }
    }

    $attributes = [];
    if ($node->hasAttributes()) {
      foreach ($node->attributes as $attr) {
        $namespace = FALSE;
        if (($pos = strpos($attr->nodeName, ':')) !== FALSE) {
          $namespace = substr($attr->nodeName, 0, $pos);
          if (!isset($used_namespaces[$namespace])) {
            $used_namespaces[$namespace] = $namespace;
            $namespaces[$namespace] = $namespace;
          }
        }
        $attributes[$attr->nodeName] = [
          'name' => $attr->nodeName,
          'sort_name' => $namespace ? substr($attr->nodeName, $pos + 1) : $attr->nodeName,
          'value' => $attr->nodeValue,
        ];
      }
    }

    $output = '<' . $node->nodeName;

    if (!empty($namespaces)) {
      sort($namespaces);
      foreach ($namespaces as $prefix) {
        if (empty($prefix)) {
          $output .= ' xmlns="' . self::XMLNS[''] . '"';
        }
        else {
          $output .= ' xmlns:' . $prefix . '="' . self::XMLNS[$prefix] . '"';
        }
      }
    }

    if (!empty($attributes)) {
      usort($attributes, 'self::alphaSort');
      foreach ($attributes as $attribute) {
        $output .= ' ' . $attribute['name'] . '="' . $attribute['value'] . '"';
      }
    }

    $output .= '>';

    // Get NODE type children.
    $childNodes = [];
    for ($i = 0; $i < $node->childNodes->length; $i++) {
      if ($node->childNodes->item($i)->nodeType === XML_ELEMENT_NODE) {
        $childNodes[] = $node->childNodes->item($i);
      }
    }

    if (!empty($childNodes)) {
      foreach ($childNodes as $childNode) {
        $output .= $this->exclusiveCanonicalization($childNode, $used_namespaces);
      }
    }
    else {
      $output .= $node->nodeValue;
    }

    $output .= '</' . $node->nodeName . '>';

    return $output;
  }

  /**
   * Helper sorting function.
   */
  public static function alphaSort($x, $y) {
    return strcasecmp($x['sort_name'], $y['sort_name']);
  }

}
