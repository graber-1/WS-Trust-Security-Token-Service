<?php

namespace AgivServices\Factory;

/**
 * Defines Agiv service factory interface.
 */
interface AgivServiceFactoryInterface {

  /**
   * Service getter function.
   *
   * @var string $serviceClass
   *   Name of the constructed service class.
   * @var mixed $data
   *   Additional data used to create the service.
   */
  public static function getService($serviceClass, $data);

}
