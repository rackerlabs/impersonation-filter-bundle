package org.openrepose.filters.impersonation

import java.io.ByteArrayInputStream
import java.net.URL
import javax.servlet.http.HttpServletResponse

import com.mockrunner.mock.web.{MockFilterChain, MockFilterConfig, MockHttpServletRequest, MockHttpServletResponse}
import com.rackspace.httpdelegation.HttpDelegationManager
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
import org.openrepose.core.services.serviceclient.akka.AkkaServiceClient
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

    it("Impersonates a user allowing through the filter") {
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

      //doReturn(adminResponse)
      //  .when(mockAkkaService)
      //  .post(
      //    any[String],MM.eq(s"${configuration.getAuthenticationServer.getHref}${ImpersonationHandler.TOKEN_ENDPOINT}"), any[java.util.Map[String, String]], any[String], any[javax.ws.rs.core.MediaType])

      /*doReturn(impersonationResponse).
      when(mockAkkaService)
        .post(
          any[String],MM.eq(s"${configuration.getAuthenticationServer.getHref}${ImpersonationHandler.IMPERSONATION_ENDPOINT}"), any[java.util.Map[String, String]], any[String], any[javax.ws.rs.core.MediaType]
        )*/

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

}
