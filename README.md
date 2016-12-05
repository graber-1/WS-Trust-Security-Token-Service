INTRODUCTION
------------

This is a library to Get Security tokens fron Agiv-STS service
and use them in service classes.

So far The STS part is done, but work with first service (Gipod)
is still in progress.


TODO
----

Figure out how to calculate signature value for Gipod request.
Method: hmac-sha1.

With testing timestamp values and test cache the signatureValue
must be equal to the value in /data/gipod_request.xml


TESTING INFORMATION
-------------------

Folder /data contains a set of requests and response that worked
with use of .NET application. Documents were captured using Fiddler.

To emulate those requests, use timestamp values from comments in:
 * /AgivSTSRequest.php l. 144
 * /services/GipodService.php l. 171
AND use cache ID "test" (will expire in more than 20 years) in /services/GipodService.php l. 68.


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

Codebreaker class is used only for development.
