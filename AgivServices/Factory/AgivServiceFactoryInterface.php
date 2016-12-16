<?php

namespace AgivServices\Factory;

/**
 * Defines Agiv service factory interface.
 */
interface AgivServiceFactoryInterface {

  /**
   * Service getter function.
   */
  public static function getService($serviceClass, $data);

}
