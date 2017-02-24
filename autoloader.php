<?php

/**
 * @file
 * Autoload library classes.
 */

// Conditional autoloader is used to prevent conflicts with other
// autoloaders of the application.
spl_autoload_register(function ($class) {
  if (substr($class, 0, 4) === 'Agiv') {
    require_once strtr($class, ['\\' => '/']) . '.php';
  }
});
