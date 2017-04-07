<?php

namespace AgivSTS;

/**
 * Defines Agiv service factory interface.
 */
interface AgivCacheInterface {

  /**
   * Get cache.
   *
   * @param string $cache_id
   *   Cache identifier.
   *
   * @return array
   *   Cached data.
   */
  public function cacheGet($cache_id);

  /**
   * Set cache.
   *
   * @param string $cache_id
   *   Cache identifier.
   * @param mixed $token
   *   Agiv security token.
   */
  public function cacheSet($cache_id, $token);

}
