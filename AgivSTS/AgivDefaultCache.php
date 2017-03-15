<?php

namespace AgivSTS;

use AgivSTS\Exception\AgivException;

/**
 * Defines default security token cache mechanism.
 */
class AgivDefaultCache implements AgivCacheInterface {

  // Safety timespan for token expiration.
  const SAFETY_TIMESPAN = 30;

  // Local file cache path.
  const CACHE_PATH = __DIR__ . '/../cache';

  /**
   * Get cache.
   */
  public function cacheGet($cache_id) {
    $filename = 'cache' . (empty($cache_id) ? '' : '_' . $cache_id) . '.dat';
    $path = self::CACHE_PATH . '/' . $filename;
    if (file_exists($path)) {
      $data = unserialize(file_get_contents($path));
      if (isset($data['lifetime']) && $data['lifetime']['Expires'] > (time() - self::SAFETY_TIMESPAN)) {
        return $data;
      }
    }
    return FALSE;
  }

  /**
   * Set cache.
   */
  public function cacheSet($cache_id, $token) {

    if (!file_exists(self::CACHE_PATH)) {
      mkdir(self::CACHE_PATH, 0775);
    }
    if (!is_writable(self::CACHE_PATH)) {
      chmod(self::CACHE_PATH, 0775);
    }

    if (is_writable(self::CACHE_PATH)) {
      $filename = 'cache' . (empty($cache_id) ? '' : '_' . $cache_id) . '.dat';
      $path = self::CACHE_PATH . '/' . $filename;

      $data = array(
        'lifetime' => $token->get('lifetime'),
        'xml' => $token->get('rawData'),
      );
      $result = file_put_contents($path, serialize($data));
    }
    else {
      throw new AgivException('Default cache directory is not writable.');
    }
  }

}
