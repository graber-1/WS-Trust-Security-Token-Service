<?php

namespace AgivServices\Factory;

use AgivSTS\Exception\AgivException;
use AgivSTS\AgivSecurityToken;
use AgivSTS\AgivDefaultCache;

/**
 * Defines default Agiv service factory.
 */
class AgivDefaultServiceFactory implements AgivServiceFactoryInterface {

  /**
   * {@inheritdoc}
   */
  public function getService($serviceClass, $data) {
    $serviceClass = '\\AgivServices\\' . $serviceClass;

    if (class_exists($serviceClass)) {
      $stsObjectData = [
        'realm' => $serviceClass::CONSTRUCTOR_DEFAULTS['realm'],
        'cacheObject' => new AgivDefaultCache(),
        'certPath' => $data['certPath'],
        'pkPath' => $data['pkPath'],
      ];
      $data['agivSecurityToken'] = new AgivSecurityToken($stsObjectData);

      return new $serviceClass($data);
    }
    else {
      throw new AgivException('Service class %s does not exist.', $serviceClass);
    }
  }

}
