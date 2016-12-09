<?php

namespace AgivSTS;

/**
 * Defines Agiv service factory interface.
 */
interface AgivCacheInterface {

  /**
   * Get cache.
   */
  public function cacheGet($cache_id, $token);

  /**
   * Set cache.
   */
  public function cacheSet($cache_id, $token);

}
