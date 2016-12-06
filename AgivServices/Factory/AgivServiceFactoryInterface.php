<?php

namespace AgivServices\Factory;

/**
 * Defines Agiv service factory interface.
 */
interface AgivServiceFactoryInterface {

  /**
   * Service getter function.
   */
  public function getService($serviceClass, $data);

}
