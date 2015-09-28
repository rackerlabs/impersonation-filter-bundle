package features.impersonation

import framework.ReposeValveTest
import framework.mocks.MockIdentityService
import org.joda.time.DateTime
import org.rackspace.deproxy.Deproxy
import org.rackspace.deproxy.Endpoint
import org.rackspace.deproxy.Response
import spock.lang.Unroll

/**
 * Created by dimi5963 on 8/11/15.
 */
class ImpersonationWithDelegationTest extends ReposeValveTest {
    static Endpoint identityEndpoint

    def static MockIdentityService fakeIdentityService

    def setupSpec() {
        deproxy = new Deproxy()
        deproxy.addEndpoint(properties.targetPort)

        fakeIdentityService = new MockIdentityService(properties.identityPort, properties.targetPort)
        identityEndpoint = deproxy.addEndpoint(
                properties.identityPort, 'identity service', null, fakeIdentityService.handler)

        def params = properties.defaultTemplateParams
        repose.configurationProvider.applyConfigs("common", params)
        repose.configurationProvider.applyConfigs("features/impersonation/delegable", params)
        repose.start()
        repose.waitForNon500FromUrl(reposeEndpoint)
    }

    def setup() {
        sleep 500
        fakeIdentityService.resetHandlers()
    }

    def cleanupSpec() {
        deproxy.shutdown()
        repose.stop()
    }

    def cleanup() {
        deproxy._removeEndpoint(identityEndpoint)
    }

    @Unroll("Admin fail scenarios - request: #requestMethod #requestURI -d #requestBody will return #responseCode with #responseMessage")
    def "When running with failing admin requests"() {
        given: "set up identity response"
        fakeIdentityService.with {
            client_tenant = reqTenant
            client_userid = reqTenant
            client_token = UUID.randomUUID().toString()
            tokenExpiresAt = DateTime.now().plusDays(1)

        }

        fakeIdentityService.generateTokenHandler = {
            request, xml ->
                new Response(adminResponseCode, null, null, adminIdentityResponseBody)
        }

        when: "User passes request through repose"
        def mc = deproxy.makeRequest([
                url: reposeEndpoint + requestURI,
                method: requestMethod,
                requestBody: requestBody,
                headers: headers
        ])

        then: "Pass all the things"
        mc.orphanedHandlings.size == 1
        mc.orphanedHandlings[0].response.code == adminResponseCode.toString()
        mc.orphanedHandlings[0].response.message == responseMessage
        mc.receivedResponse.code == responseCode
        mc.receivedResponse.message == clientResponseMessage

        where:

        reqTenant | adminResponseCode | adminIdentityResponseBody                      | requestMethod | requestURI | requestBody | headers                 | responseCode | responseMessage         | clientResponseMessage
        100       | 500               | ""                                             | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "401"        | "Internal Server Error" | "X-User-Name header not found"
        101       | 500               | null                                           | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "401"        | "Internal Server Error" | "X-User-Name header not found"
        102       | 404               | fakeIdentityService.identityFailureXmlTemplate | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "401"        | "Not Found"             | "X-User-Name header not found"
        103       | 401               | fakeIdentityService.identityFailureXmlTemplate | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "401"        | "Unauthorized"          | "X-User-Name header not found"
        //102       | 200               | fakeIdentityService.identitySuccessXmlTemplate | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "500"        | "Internal Server Error"
    }

    @Unroll("User fail scenarios - request: #requestMethod #requestURI -d #requestBody will return #responseCode with #responseMessage")
    def "When running with failing token requests"() {
        given: "set up identity response"
        fakeIdentityService.with {
            client_tenant = reqTenant
            client_userid = reqTenant
            client_token = UUID.randomUUID().toString()
            tokenExpiresAt = DateTime.now().plusDays(1)

        }

        //user request
        fakeIdentityService.validateTokenHandler = {
            tokenId, request, xml ->
                new Response(validateResponseCode, null, null, validateIdentityResponseBody)
        }

        when: "User passes request through repose"
        def mc = deproxy.makeRequest([
                url: reposeEndpoint + requestURI,
                method: requestMethod,
                requestBody: requestBody,
                headers: headers
        ])

        then: "Pass all the things"
        mc.orphanedHandlings.size == orphanedHandlings
        mc.receivedResponse.code == responseCode
        mc.receivedResponse.message == responseMessage

        where:

        reqTenant | validateResponseCode | validateIdentityResponseBody                   | requestMethod | requestURI | requestBody | headers                 | responseCode | responseMessage                 | orphanedHandlings
        200       | 500                  | ""                                             | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "401"        | "X-User-Name header not found"  | 2 //first time needs to admin auth
        201       | 500                  | null                                           | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "401"        | "X-User-Name header not found"  | 1
        202       | 404                  | fakeIdentityService.identityFailureXmlTemplate | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "401"        | "X-User-Name header not found"  | 1
        203       | 401                  | fakeIdentityService.identityFailureXmlTemplate | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "401"        | "X-User-Name header not found"  | 2 //401 means unauthed
        //102       | 200               | fakeIdentityService.identitySuccessXmlTemplate | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "500"        | "Internal Server Error"
    }


    @Unroll("Impersonation scenarios - request: #requestMethod #requestURI -d #requestBody will return #responseCode with #responseMessage")
    def "When running with impersonation requests"() {
        given: "set up identity response"
        def impersonatedToken = UUID.randomUUID().toString()
        fakeIdentityService.with {
            client_tenant = reqTenant
            client_userid = reqTenant
            client_token = UUID.randomUUID().toString()
            tokenExpiresAt = DateTime.now().plusDays(1)
            impersonated_token = impersonatedToken
        }

        //impersonation request
        if(validateResponseCode > 200) {
            fakeIdentityService.impersonateTokenHandler = {
                request, xml ->
                    new Response(validateResponseCode, null, null, validateIdentityResponseBody)
            }
        }

        when: "User passes request through repose"
        def mc = deproxy.makeRequest([
                url: reposeEndpoint + requestURI,
                method: requestMethod,
                requestBody: requestBody,
                headers: headers
        ])

        then: "Pass all the things"
        mc.orphanedHandlings.size == orphanedHandlings
        mc.receivedResponse.code == responseCode
        mc.receivedResponse.message == responseMessage

        if(validateResponseCode == 200){
            //validate x-auth-token is impersonated
            assert mc.handlings[0].request.headers.contains("x-auth-token")
            assert mc.handlings[0].request.headers.getFirstValue("x-auth-token") == impersonatedToken
        }

        where:

        reqTenant | validateResponseCode | validateIdentityResponseBody                               | requestMethod | requestURI | requestBody | headers                 | responseCode | responseMessage                                              | orphanedHandlings
        300       | 500                  | ""                                                         | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "502"        | "Identity Service not available to get impersonation token"  | 4 //first time needs to admin auth
        301       | 500                  | null                                                       | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "502"        | "Identity Service not available to get impersonation token"  | 1
        302       | 404                  | fakeIdentityService.impersonateTokenJsonFailedAuthTemplate | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "401"        | "Unable to find username in Identity."                       | 1
        303       | 401                  | fakeIdentityService.impersonateTokenJsonFailedAuthTemplate | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "500"        | "Unable to authenticate your admin user"                     | 2 //401 means unauthed
        304       | 200                  | ""                                                         | "GET"         | "/"        | ""          | ['x-auth-token': '123'] | "200"        | "OK"                                                         | 1
    }
}