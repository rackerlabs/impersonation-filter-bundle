Repose Impersonation filter
=================

This repo hosts Impersonation filter that can be used to take a user's token, impersonate it and forward an impersonated token to the origin service.

Steps
------

### Happy flow:

1 user sends request to magnum api
2 repose intercepts the request and attempts to authenticate token
3 if successful, repose attempts to retrieve impersonation token based on user token from cache.
4 if not exists or expiry date is < now, get impersonation token from Identity (http://docs-internal.rackspace.com/auth/api/v2.0/auth-admin-devguide/content/POST_impersonateUser_v2.0_RAX-AUTH_impersonation-tokens_Impersonation_Calls.html)
5 if successful, repose caches impersonation token withe key being user token {'usertoken': '{token: impersonatedtoken, expiry: date}'}
6 request is passed to magnum with impersonated token in place of user token (X-Auth-Token)

### Fraud/expired flow:

1 user sends request to magnum api
2 repose intercepts the request and attempts to auth token
3 repose gets back a 404 from Identity
4 repose invalidates for user token and returns 401
