<?php

namespace AgivSTS\Exception;

use \Exception;

/**
 * Agiv exception class that contains error data.
 */
class AgivException extends Exception {

  /**
   * An array containing additional error data.
   *
   * @var array
   */
  public $faultData;

  /**
   * Override constructor class to allow fault codes.
   */
  public function __construct($message, $fault_data = [], Exception $previous = NULL) {
    $this->faultData = $fault_data;
    parent::__construct($message, 0, $previous);
  }

}
