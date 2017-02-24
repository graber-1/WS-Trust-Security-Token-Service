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
  public static function getService($serviceClass, $data) {
    $serviceClass = '\\AgivServices\\' . $serviceClass;

    if (class_exists($serviceClass)) {
      $stsObjectData = [
        'realm' => $serviceClass::CONSTRUCTOR_DEFAULTS['realm'],
        'cacheObject' => new AgivDefaultCache(),
        'certPath' => $data['certPath'],
        'pkPath' => $data['pkPath'],
        'settings' => [
          'call_timeout' => 30,
        ],
      ];
      $data['agivSecurityToken'] = new AgivSecurityToken($stsObjectData);

      // Apply default settings.
      if (!isset($data['settings'])) {
        $data['settings'] = [];
      }
      $data['settings'] += [
        'call_timeout' => 30,
        'max_service_attempts' => 1,
      ];

      return new $serviceClass($data);
    }
    else {
      throw new AgivException('Service class %s does not exist.', $serviceClass);
    }
  }

}
