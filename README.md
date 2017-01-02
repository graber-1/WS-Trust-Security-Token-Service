INTRODUCTION
------------

This is a library to Get Security tokens fron Agiv-STS service
and use them in service classes.

So far we have one class to access Gipod service.

TODO
----

 * No new guidelines atm.


DRUPAL 8 WRAPPER
----------------

When the module is enabled, we have a test URL: /gipod/test.

Without parameters it attempts to get a security token and call the Gipod service.
With ?xml=g query parameter it returns the Gipod request xml.
With other ?xml parameter values it returns the Agiv STS request xml.

The test callback method uses kdpm() function
from developer_console module for exception display.
Can be replaced with kint() or dpm() when devel is preferred.


ADDITIONAL INFO
---------------

Important note:

When executing Gipod methods, parameter order is important and must be the same as on Gipod docs page.


THANKS TO
---------

 * Hans Zandbelt and his php-ws-trust-client library (https://github.com/zandbelt/php-ws-trust-client)
 * Rob Richards and his XML Security PHP library (https://github.com/robrichards/xmlseclibs)
