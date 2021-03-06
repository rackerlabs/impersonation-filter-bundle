package org.openrepose.filters.impersonation

import java.io.ByteArrayInputStream
import java.net.URL
import java.util.concurrent.TimeUnit
import javax.servlet.http.HttpServletResponse

import com.mockrunner.mock.web.{MockFilterChain, MockFilterConfig, MockHttpServletRequest, MockHttpServletResponse}
import com.rackspace.httpdelegation.{HttpDelegationHeaderNames, HttpDelegationManager}
import org.joda.time.DateTime
import org.junit.Ignore
import org.junit.runner.RunWith
import org.mockito.{Matchers => MM}
import org.mockito.Matchers._
import org.mockito.Mockito._
import org.openrepose.commons.utils.http.{CommonHttpHeader, ServiceClientResponse, OpenStackServiceHeader}
import org.openrepose.commons.utils.servlet.http.MutableHttpServletRequest
import org.openrepose.core.services.config.ConfigurationService
import org.openrepose.core.services.datastore.{Datastore, DatastoreService}
import org.openrepose.core.services.serviceclient.akka.{AkkaServiceClientException, AkkaServiceClient}
import org.openrepose.core.systemmodel.SystemModel
import org.openrepose.filters.IdentityResponses
import org.openrepose.filters.config.RackspaceImpersonation
import org.scalatest.junit.JUnitRunner
import org.scalatest.mock.MockitoSugar
import org.scalatest.{BeforeAndAfter, FunSpec}



/**
 * Created by dimi5963 on 9/22/15.
 */
@RunWith(classOf[JUnitRunner])
class ImpersonationFilterTest extends FunSpec
with org.scalatest.Matchers
with BeforeAndAfter
with MockitoSugar
with IdentityResponses
with HttpDelegationManager {

  val mockDatastoreService = mock[DatastoreService]
  private val mockDatastore: Datastore = mock[Datastore]
  when(mockDatastoreService.getDefaultDatastore).thenReturn(mockDatastore)
  val mockConfigService = mock[ConfigurationService]
  val mockSystemModel = mock[SystemModel]
  when(mockSystemModel.isTracingHeader).thenReturn(true, Nil: _*)
  private final val dateTime = DateTime.now().plusHours(1)

  val mockAkkaService = mock[AkkaServiceClient]

  before {
    reset(mockDatastore)
    reset(mockConfigService)
    reset(mockAkkaService)
  }

  after {
    //verify(mockAkkaService)
  }

  describe("Filter lifecycle") {
    val filter: ImpersonationFilter = new ImpersonationFilter(mockConfigService, mockAkkaService, mockDatastoreService)
    val config: MockFilterConfig = new MockFilterConfig

    it("should throw 500 if filter is not initialized") {
      val request = new MockHttpServletRequest
      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain
      filter.isInitialized shouldBe false
      filter.doFilter(request, response, filterChain)
      response.getErrorCode shouldBe HttpServletResponse.SC_INTERNAL_SERVER_ERROR
    }

    it("should subscribe a listener to the configuration service on init") {
      filter.init(config)

      verify(mockConfigService).subscribeTo(
        anyString(),
        anyString(),
        any[URL],
        any(),
        any[Class[RackspaceImpersonation]]
      )
      verify(mockConfigService).subscribeTo(
        anyString(),
        any[URL],
        any(),
        any[Class[SystemModel]]
      )
    }

    it("should unsubscribe a listener to the configuration service on destroy") {
      filter.destroy()

      verify(mockConfigService, times(2)).unsubscribeFrom(
        anyString(),
        any()
      )
    }
  }

  describe("Configured with only required values") {
    def configuration = Marshaller.impersonationConfigFromString(
      """<?xml version="1.0" encoding="UTF-8"?>
        |<rackspace-impersonation xmlns="http://docs.openrepose.org/repose/impersonation/v1.0">
        |    <authentication-server
        |            username="username"
        |            password="password"
        |            href="https://some.identity.com"
        |            />
        |</rackspace-impersonation>
      """.stripMargin)

    val filter: ImpersonationFilter = new ImpersonationFilter(mockConfigService, mockAkkaService, mockDatastoreService)

    val config: MockFilterConfig = new MockFilterConfig
    filter.init(config)
    filter.ImpersonationConfigListener.configurationUpdated(configuration)
    filter.SystemModelConfigListener.configurationUpdated(mockSystemModel)

    it("Impersonates a user allowing through the filter and creates new header") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn(null, "glibglob")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(200, new ByteArrayInputStream(impersonateTokenResponse().getBytes()))
      val adminResponse = new ServiceClientResponse(200, new ByteArrayInputStream(adminAuthenticationTokenResponse().getBytes()))

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(adminResponse, impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest shouldNot be(null)
      filterChain.getLastResponse shouldNot be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(CommonHttpHeader.AUTH_TOKEN.toString).getValue shouldEqual VALID_TOKEN
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(OpenStackServiceHeader.USER_NAME.toString).getValue shouldEqual VALID_USER
    }

  }


  describe("Configured simply to impersonate users") {
    //Configure the filter
    def configuration = Marshaller.impersonationConfigFromString(
      """<?xml version="1.0" encoding="UTF-8"?>
        |<rackspace-impersonation xmlns="http://docs.openrepose.org/repose/impersonation/v1.0">
        |    <authentication-server
        |            username="username"
        |            password="password"
        |            href="https://some.identity.com"
        |            impersonation-ttl="600"
        |            />
        |</rackspace-impersonation>
      """.stripMargin)

    val filter: ImpersonationFilter = new ImpersonationFilter(mockConfigService, mockAkkaService, mockDatastoreService)

    val config: MockFilterConfig = new MockFilterConfig
    filter.init(config)
    filter.ImpersonationConfigListener.configurationUpdated(configuration)
    filter.SystemModelConfigListener.configurationUpdated(mockSystemModel)

    it("Impersonates a user allowing through the filter and creates new header") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn(null, "glibglob")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(200, new ByteArrayInputStream(impersonateTokenResponse().getBytes()))
      val adminResponse = new ServiceClientResponse(200, new ByteArrayInputStream(adminAuthenticationTokenResponse().getBytes()))

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(adminResponse, impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest shouldNot be(null)
      filterChain.getLastResponse shouldNot be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(CommonHttpHeader.AUTH_TOKEN.toString).getValue shouldEqual VALID_TOKEN
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(OpenStackServiceHeader.USER_NAME.toString).getValue shouldEqual VALID_USER
    }

    it("Impersonates a user allowing through the filter and updates existing header") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)
      request.addHeader(CommonHttpHeader.AUTH_TOKEN.toString, "this-is-random")
      request.addHeader(OpenStackServiceHeader.X_EXPIRATION.toString, dateTime.toString)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn(null, "glibglob")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(200, new ByteArrayInputStream(impersonateTokenResponse().getBytes()))
      val adminResponse = new ServiceClientResponse(200, new ByteArrayInputStream(adminAuthenticationTokenResponse().getBytes()))

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(adminResponse, impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest shouldNot be(null)
      filterChain.getLastResponse shouldNot be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(CommonHttpHeader.AUTH_TOKEN.toString).getValue shouldEqual VALID_TOKEN
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(OpenStackServiceHeader.USER_NAME.toString).getValue shouldEqual VALID_USER
    }

    it("Retrieves impersonation token from cache if exists in datastore") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      val impersonationToken = ImpersonationHandler.ImpersonationToken(dateTime.toString, VALID_TOKEN)

      when(mockDatastore.get(s"${ImpersonationHandler.IMPERSONATION_KEY_PREFIX}$VALID_USER")).thenReturn(impersonationToken, null)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest shouldNot be(null)
      filterChain.getLastResponse shouldNot be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(CommonHttpHeader.AUTH_TOKEN.toString).getValue shouldEqual VALID_TOKEN
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(OpenStackServiceHeader.USER_NAME.toString).getValue shouldEqual VALID_USER
    }

    it("Impersonates a user with cached admin token") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      val impersonationToken = ImpersonationHandler.ImpersonationToken(dateTime.toString, VALID_TOKEN)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn("test", "test", "test")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(200, new ByteArrayInputStream(impersonateTokenResponse().getBytes()))

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest shouldNot be(null)
      filterChain.getLastResponse shouldNot be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(CommonHttpHeader.AUTH_TOKEN.toString).getValue shouldEqual VALID_TOKEN
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(OpenStackServiceHeader.USER_NAME.toString).getValue shouldEqual VALID_USER
    }

    it("Impersonates a user and passes down trace id when specified") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)
      request.addHeader(CommonHttpHeader.TRACE_GUID.toString, "valid-trace-guid")

      val impersonationToken = ImpersonationHandler.ImpersonationToken(dateTime.toString, VALID_TOKEN)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn("test", "test", "test")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(200, new ByteArrayInputStream(impersonateTokenResponse().getBytes()))

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest shouldNot be(null)
      filterChain.getLastResponse shouldNot be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(CommonHttpHeader.AUTH_TOKEN.toString).getValue shouldEqual VALID_TOKEN
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(OpenStackServiceHeader.USER_NAME.toString).getValue shouldEqual VALID_USER
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(CommonHttpHeader.TRACE_GUID.toString).getValue shouldEqual "valid-trace-guid"
    }

    it("Does not impersonate if x-user-name when missing") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn(null, "glibglob")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(200, new ByteArrayInputStream(impersonateTokenResponse().getBytes()))
      val adminResponse = new ServiceClientResponse(200, new ByteArrayInputStream(adminAuthenticationTokenResponse().getBytes()))

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(adminResponse, impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest should be(null)
      filterChain.getLastResponse should be(null)
      response.getErrorCode shouldBe HttpServletResponse.SC_UNAUTHORIZED
    }

  }


  describe("Identity requests for admin token failures") {
    //Configure the filter
    def configuration = Marshaller.impersonationConfigFromString(
      """<?xml version="1.0" encoding="UTF-8"?>
        |<rackspace-impersonation xmlns="http://docs.openrepose.org/repose/impersonation/v1.0">
        |    <authentication-server
        |            username="username"
        |            password="password"
        |            href="https://some.identity.com"
        |            impersonation-ttl="600"
        |            />
        |</rackspace-impersonation>
      """.stripMargin)

    val filter: ImpersonationFilter = new ImpersonationFilter(mockConfigService, mockAkkaService, mockDatastoreService)

    val config: MockFilterConfig = new MockFilterConfig
    filter.init(config)
    filter.ImpersonationConfigListener.configurationUpdated(configuration)
    filter.SystemModelConfigListener.configurationUpdated(mockSystemModel)


    it("Does not impersonate if admin auth request is not found") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      //Pretend like identity is going to give us a valid admin token
      val adminResponse = new ServiceClientResponse(
        HttpServletResponse.SC_NOT_FOUND, null)

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(adminResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest should be(null)
      filterChain.getLastResponse should be(null)
      response.getErrorCode shouldBe HttpServletResponse.SC_INTERNAL_SERVER_ERROR
    }

    it("Does not impersonate if admin auth request is internal server error") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      //Pretend like identity is going to give us a valid admin token
      val adminResponse = new ServiceClientResponse(
        HttpServletResponse.SC_INTERNAL_SERVER_ERROR, null)

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(adminResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest should be(null)
      filterChain.getLastResponse should be(null)
      response.getErrorCode shouldBe HttpServletResponse.SC_BAD_GATEWAY
    }

    it("Does not impersonate if admin auth request is rate limited") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      //Pretend like identity is going to give us a valid admin token
      val adminResponse = new ServiceClientResponse(
        HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE, null)

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(adminResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest should be(null)
      filterChain.getLastResponse should be(null)
      response.getErrorCode shouldBe HttpServletResponse.SC_SERVICE_UNAVAILABLE
    }

    it("Does not impersonate if admin auth response is invalid") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      //Pretend like identity is going to give us a valid admin token
      val adminResponse = new ServiceClientResponse(
        HttpServletResponse.SC_OK, new ByteArrayInputStream("{}".getBytes()))

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(adminResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest should be(null)
      filterChain.getLastResponse should be(null)
      response.getErrorCode shouldBe HttpServletResponse.SC_BAD_GATEWAY
    }

    it("Does not impersonate if admin auth response is null") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest should be(null)
      filterChain.getLastResponse should be(null)
      response.getErrorCode shouldBe HttpServletResponse.SC_INTERNAL_SERVER_ERROR
    }

    it("Does not impersonate if admin auth response throws AkkaServiceClientException") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      val impersonationToken = ImpersonationHandler.ImpersonationToken(dateTime.toString, VALID_TOKEN)

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenThrow(new AkkaServiceClientException("fail", null))

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)
      response.getErrorCode should be(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)

      filterChain.getLastRequest should be(null)
      filterChain.getLastResponse should be(null)
    }
  }

  describe("Identity requests for impersonation token failures") {
    //Configure the filter
    def configuration = Marshaller.impersonationConfigFromString(
      """<?xml version="1.0" encoding="UTF-8"?>
        |<rackspace-impersonation xmlns="http://docs.openrepose.org/repose/impersonation/v1.0">
        |    <authentication-server
        |            username="username"
        |            password="password"
        |            href="https://some.identity.com"
        |            impersonation-ttl="600"
        |            />
        |</rackspace-impersonation>
      """.stripMargin)

    val filter: ImpersonationFilter = new ImpersonationFilter(mockConfigService, mockAkkaService, mockDatastoreService)

    val config: MockFilterConfig = new MockFilterConfig
    filter.init(config)
    filter.ImpersonationConfigListener.configurationUpdated(configuration)
    filter.SystemModelConfigListener.configurationUpdated(mockSystemModel)


    it("Does not impersonate if user is not found") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      val impersonationToken = ImpersonationHandler.ImpersonationToken(dateTime.toString, VALID_TOKEN)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn("test", "test", "test")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(
        HttpServletResponse.SC_NOT_FOUND, null)

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      response.getErrorCode should be(HttpServletResponse.SC_UNAUTHORIZED)

      filterChain.getLastRequest should be(null)
      filterChain.getLastResponse should be(null)
    }

    it("Does not impersonate if admin token is unauthenticated") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      val impersonationToken = ImpersonationHandler.ImpersonationToken(dateTime.toString, VALID_TOKEN)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn("test1", null, null)
      when(mockDatastore.remove(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn(true)

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(
        HttpServletResponse.SC_UNAUTHORIZED, null)
      val adminResponse = new ServiceClientResponse(
        HttpServletResponse.SC_NOT_FOUND, null)


      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(impersonationResponse, adminResponse, impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)
      response.getErrorCode should be(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)

      filterChain.getLastRequest should be(null)
      filterChain.getLastResponse should be(null)
    }

    it("Does not impersonate if identity request bombed") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      val impersonationToken = ImpersonationHandler.ImpersonationToken(dateTime.toString, VALID_TOKEN)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn("test", "test", "test")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(
        HttpServletResponse.SC_INTERNAL_SERVER_ERROR, null)

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)
      response.getErrorCode should be(HttpServletResponse.SC_BAD_GATEWAY)

      filterChain.getLastRequest should be(null)
      filterChain.getLastResponse should be(null)
    }

    it("Does not impersonate if impersonation request rate limited") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      val impersonationToken = ImpersonationHandler.ImpersonationToken(dateTime.toString, VALID_TOKEN)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn("test", "test", "test")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(
        HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE, null)

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)
      response.getErrorCode should be(HttpServletResponse.SC_SERVICE_UNAVAILABLE)

      filterChain.getLastRequest should be(null)
      filterChain.getLastResponse should be(null)
    }

    it("Does not impersonate if impersonation response is invalid") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      val impersonationToken = ImpersonationHandler.ImpersonationToken(dateTime.toString, VALID_TOKEN)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn("test", "test", "test")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(
        HttpServletResponse.SC_OK, new ByteArrayInputStream("{}".getBytes()))

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)
      response.getErrorCode should be(HttpServletResponse.SC_BAD_GATEWAY)

      filterChain.getLastRequest should be(null)
      filterChain.getLastResponse should be(null)
    }

    it("Does not impersonate if impersonation response is null") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      val impersonationToken = ImpersonationHandler.ImpersonationToken(dateTime.toString, VALID_TOKEN)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn("test", "test", "test")

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)
      response.getErrorCode should be(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)

      filterChain.getLastRequest should be(null)
      filterChain.getLastResponse should be(null)
    }

    it("Does not impersonate if impersonation response throws AkkaServiceClientException") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      val impersonationToken = ImpersonationHandler.ImpersonationToken(dateTime.toString, VALID_TOKEN)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn("test", "test", "test")

      //Pretend like identity is going to give us a valid admin token
      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenThrow(new AkkaServiceClientException("fail", null))

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)
      response.getErrorCode should be(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)

      filterChain.getLastRequest should be(null)
      filterChain.getLastResponse should be(null)
    }
  }

  describe("TTL") {

    it("Impersonates a user allowing through the filter and creates new header and caches forever with 0 ttl") {
      def configuration = Marshaller.impersonationConfigFromString(
        """<?xml version="1.0" encoding="UTF-8"?>
          |<rackspace-impersonation xmlns="http://docs.openrepose.org/repose/impersonation/v1.0">
          |    <authentication-server
          |            username="username"
          |            password="password"
          |            href="https://some.identity.com"
          |            impersonation-ttl="0"
          |            />
          |</rackspace-impersonation>
        """.stripMargin)

      val filter: ImpersonationFilter = new ImpersonationFilter(mockConfigService, mockAkkaService, mockDatastoreService)

      val config: MockFilterConfig = new MockFilterConfig
      filter.init(config)
      filter.ImpersonationConfigListener.configurationUpdated(configuration)
      filter.SystemModelConfigListener.configurationUpdated(mockSystemModel)

      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn(null, "glibglob")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(200, new ByteArrayInputStream(impersonateTokenResponse().getBytes()))
      val adminResponse = new ServiceClientResponse(200, new ByteArrayInputStream(adminAuthenticationTokenResponse().getBytes()))

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(adminResponse, impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest shouldNot be(null)
      filterChain.getLastResponse shouldNot be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(CommonHttpHeader.AUTH_TOKEN.toString).getValue shouldEqual VALID_TOKEN
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(OpenStackServiceHeader.USER_NAME.toString).getValue shouldEqual VALID_USER
      verify(mockDatastore, times(1)).put(anyString(), any[Serializable])
      verify(mockDatastore, times(1)).put(anyString(), any[Serializable], anyInt(), any[TimeUnit])
    }

    it("Impersonates a user allowing through the filter and creates new header but does not cache with -1 ttl") {
      def configuration = Marshaller.impersonationConfigFromString(
        """<?xml version="1.0" encoding="UTF-8"?>
          |<rackspace-impersonation xmlns="http://docs.openrepose.org/repose/impersonation/v1.0">
          |    <authentication-server
          |            username="username"
          |            password="password"
          |            href="https://some.identity.com"
          |            impersonation-ttl="-1"
          |            />
          |</rackspace-impersonation>
        """.stripMargin)

      val filter: ImpersonationFilter = new ImpersonationFilter(mockConfigService, mockAkkaService, mockDatastoreService)

      val config: MockFilterConfig = new MockFilterConfig
      filter.init(config)
      filter.ImpersonationConfigListener.configurationUpdated(configuration)
      filter.SystemModelConfigListener.configurationUpdated(mockSystemModel)

      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn(null, "glibglob")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(200, new ByteArrayInputStream(impersonateTokenResponse().getBytes()))
      val adminResponse = new ServiceClientResponse(200, new ByteArrayInputStream(adminAuthenticationTokenResponse().getBytes()))

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(adminResponse, impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest shouldNot be(null)
      filterChain.getLastResponse shouldNot be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(CommonHttpHeader.AUTH_TOKEN.toString).getValue shouldEqual VALID_TOKEN
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(OpenStackServiceHeader.USER_NAME.toString).getValue shouldEqual VALID_USER
      verify(mockDatastore, times(1)).put(anyString(), any[Serializable])
      verify(mockDatastore, never()).put(anyString(), any[Serializable], anyInt(), any[TimeUnit])
    }

    it("Impersonates a user but doesn't cache because token ttl < config ttl") {
      def configuration = Marshaller.impersonationConfigFromString(
        """<?xml version="1.0" encoding="UTF-8"?>
          |<rackspace-impersonation xmlns="http://docs.openrepose.org/repose/impersonation/v1.0">
          |    <authentication-server
          |            username="username"
          |            password="password"
          |            href="https://some.identity.com"
          |            impersonation-ttl="300"
          |            />
          |</rackspace-impersonation>
        """.stripMargin)

      val filter: ImpersonationFilter = new ImpersonationFilter(mockConfigService, mockAkkaService, mockDatastoreService)

      val config: MockFilterConfig = new MockFilterConfig
      filter.init(config)
      filter.ImpersonationConfigListener.configurationUpdated(configuration)
      filter.SystemModelConfigListener.configurationUpdated(mockSystemModel)

      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn(null, "glibglob")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(200, new ByteArrayInputStream(impersonateTokenResponse(expires = DateTime.now()).getBytes()))
      val adminResponse = new ServiceClientResponse(200, new ByteArrayInputStream(adminAuthenticationTokenResponse().getBytes()))

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(adminResponse, impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest shouldNot be(null)
      filterChain.getLastResponse shouldNot be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(CommonHttpHeader.AUTH_TOKEN.toString).getValue shouldEqual VALID_TOKEN
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(OpenStackServiceHeader.USER_NAME.toString).getValue shouldEqual VALID_USER
      verify(mockDatastore, times(1)).put(anyString(), any[Serializable])
      verify(mockDatastore, never()).put(anyString(), any[Serializable], anyInt(), any[TimeUnit])
    }

    it("Impersonates a user allowing through the filter and creates new header but does not cache with -1 ttl and expired token") {
      def configuration = Marshaller.impersonationConfigFromString(
        """<?xml version="1.0" encoding="UTF-8"?>
          |<rackspace-impersonation xmlns="http://docs.openrepose.org/repose/impersonation/v1.0">
          |    <authentication-server
          |            username="username"
          |            password="password"
          |            href="https://some.identity.com"
          |            impersonation-ttl="-1"
          |            />
          |</rackspace-impersonation>
        """.stripMargin)

      val filter: ImpersonationFilter = new ImpersonationFilter(mockConfigService, mockAkkaService, mockDatastoreService)

      val config: MockFilterConfig = new MockFilterConfig
      filter.init(config)
      filter.ImpersonationConfigListener.configurationUpdated(configuration)
      filter.SystemModelConfigListener.configurationUpdated(mockSystemModel)

      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn(null, "glibglob")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(200, new ByteArrayInputStream(impersonateTokenResponse(expires = DateTime.now()).getBytes()))
      val adminResponse = new ServiceClientResponse(200, new ByteArrayInputStream(adminAuthenticationTokenResponse().getBytes()))

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(adminResponse, impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest shouldNot be(null)
      filterChain.getLastResponse shouldNot be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(CommonHttpHeader.AUTH_TOKEN.toString).getValue shouldEqual VALID_TOKEN
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(OpenStackServiceHeader.USER_NAME.toString).getValue shouldEqual VALID_USER
      verify(mockDatastore, times(1)).put(anyString(), any[Serializable])
      verify(mockDatastore, never()).put(anyString(), any[Serializable], anyInt(), any[TimeUnit])
    }
  }

  describe("Delegation") {
    //Configure the filter
    def configuration = Marshaller.impersonationConfigFromString(
      """<?xml version="1.0" encoding="UTF-8"?>
        |<rackspace-impersonation xmlns="http://docs.openrepose.org/repose/impersonation/v1.0">
        |    <delegating/>
        |    <authentication-server
        |            username="username"
        |            password="password"
        |            href="https://some.identity.com"
        |            />
        |</rackspace-impersonation>
      """.stripMargin)

    val filter: ImpersonationFilter = new ImpersonationFilter(mockConfigService, mockAkkaService, mockDatastoreService)

    val config: MockFilterConfig = new MockFilterConfig
    filter.init(config)
    filter.ImpersonationConfigListener.configurationUpdated(configuration)
    filter.SystemModelConfigListener.configurationUpdated(mockSystemModel)

    it("Impersonates a user allowing through the filter and creates new header") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn(null, "glibglob")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(200, new ByteArrayInputStream(impersonateTokenResponse().getBytes()))
      val adminResponse = new ServiceClientResponse(200, new ByteArrayInputStream(adminAuthenticationTokenResponse().getBytes()))

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(adminResponse, impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest shouldNot be(null)
      filterChain.getLastResponse shouldNot be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(CommonHttpHeader.AUTH_TOKEN.toString).getValue shouldEqual VALID_TOKEN
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(OpenStackServiceHeader.USER_NAME.toString).getValue shouldEqual VALID_USER
    }

    it("Does not impersonate if impersonation request rate limited but passes results in delegated filter") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      val impersonationToken = ImpersonationHandler.ImpersonationToken(dateTime.toString, VALID_TOKEN)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn("test", "test", "test")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(
        HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE, null)

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(impersonationResponse)

      val response = new MockHttpServletResponse
      response.addHeader(CommonHttpHeader.USER_AGENT.toString, "UNIT-TEST")
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)
      response.getErrorCode should be(HttpServletResponse.SC_OK)

      filterChain.getLastRequest shouldNot be(null)
      filterChain.getLastResponse shouldNot be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeader(CommonHttpHeader.AUTH_TOKEN.toString) should be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(HttpDelegationHeaderNames.Delegated.toString).getValue shouldEqual(
        "status_code=503`component=rackspace-impersonation`message=Rate limited when getting impersonation token;q=0.5")
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(OpenStackServiceHeader.USER_NAME.toString).getValue shouldEqual VALID_USER
    }
  }

  describe("Delegation with quality") {
    //Configure the filter
    def configuration = Marshaller.impersonationConfigFromString(
      """<?xml version="1.0" encoding="UTF-8"?>
        |<rackspace-impersonation xmlns="http://docs.openrepose.org/repose/impersonation/v1.0">
        |    <delegating quality="1.0"/>
        |    <authentication-server
        |            username="username"
        |            password="password"
        |            href="https://some.identity.com"
        |            />
        |</rackspace-impersonation>
      """.stripMargin)

    val filter: ImpersonationFilter = new ImpersonationFilter(mockConfigService, mockAkkaService, mockDatastoreService)

    val config: MockFilterConfig = new MockFilterConfig
    filter.init(config)
    filter.ImpersonationConfigListener.configurationUpdated(configuration)
    filter.SystemModelConfigListener.configurationUpdated(mockSystemModel)

    it("Impersonates a user allowing through the filter and creates new header") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn(null, "glibglob")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(200, new ByteArrayInputStream(impersonateTokenResponse().getBytes()))
      val adminResponse = new ServiceClientResponse(200, new ByteArrayInputStream(adminAuthenticationTokenResponse().getBytes()))

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(adminResponse, impersonationResponse)

      val response = new MockHttpServletResponse
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)

      filterChain.getLastRequest shouldNot be(null)
      filterChain.getLastResponse shouldNot be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(CommonHttpHeader.AUTH_TOKEN.toString).getValue shouldEqual VALID_TOKEN
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(OpenStackServiceHeader.USER_NAME.toString).getValue shouldEqual VALID_USER
    }

    it("Does not impersonate if impersonation request rate limited but passes results in delegated filter") {
      //make a request and validate that it called the akka service client?
      val request = new MockHttpServletRequest()
      request.addHeader(OpenStackServiceHeader.USER_NAME.toString, VALID_USER)

      val impersonationToken = ImpersonationHandler.ImpersonationToken(dateTime.toString, VALID_TOKEN)

      when(mockDatastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY)).thenReturn("test", "test", "test")

      //Pretend like identity is going to give us a valid admin token
      val impersonationResponse = new ServiceClientResponse(
        HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE, null)

      when(mockAkkaService.post(
        any[String],
        any[String],
        any[java.util.Map[String, String]],
        any[String],
        any[javax.ws.rs.core.MediaType])
      ).thenReturn(impersonationResponse)

      val response = new MockHttpServletResponse
      response.addHeader(CommonHttpHeader.RETRY_AFTER.toString, DateTime.now().toString())
      val filterChain = new MockFilterChain()
      filter.doFilter(request, response, filterChain)
      response.getErrorCode should be(HttpServletResponse.SC_OK)

      filterChain.getLastRequest shouldNot be(null)
      filterChain.getLastResponse shouldNot be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeader(CommonHttpHeader.AUTH_TOKEN.toString) should be(null)
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(HttpDelegationHeaderNames.Delegated.toString).getValue shouldEqual (
        "status_code=503`component=rackspace-impersonation`message=Rate limited when getting impersonation token;q=1.0")
      filterChain.getLastRequest.asInstanceOf[MutableHttpServletRequest].
        getHeaderValue(OpenStackServiceHeader.USER_NAME.toString).getValue shouldEqual VALID_USER
    }
  }
}
