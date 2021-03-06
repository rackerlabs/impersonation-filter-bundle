package org.openrepose.filters.impersonation

import java.util.{GregorianCalendar, Calendar}
import javax.servlet.http.{HttpServletResponse, HttpServletRequest}
import javax.ws.rs.core.MediaType

import com.fasterxml.jackson.core.JsonProcessingException
import com.typesafe.scalalogging.slf4j.LazyLogging
import org.apache.http.HttpHeaders
import org.apache.http.client.utils.DateUtils
import org.joda.time.format.ISODateTimeFormat
import org.openrepose.commons.utils.http.{ServiceClientResponse, CommonHttpHeader}
import org.openrepose.commons.utils.servlet.http.ReadableHttpServletResponse
import org.openrepose.core.filter.logic.FilterDirector
import org.openrepose.core.filter.logic.common.AbstractFilterLogicHandler
import org.openrepose.core.filter.logic.impl.FilterDirectorImpl
import org.openrepose.filters.config.RackspaceImpersonation
import org.openrepose.core.services.serviceclient.akka.AkkaServiceClient
import org.openrepose.filters.impersonation.ImpersonationHandler._

import play.api.libs.json._

import scala.collection.JavaConverters._
import scala.io.Source
import scala.util.{Failure, Success, Try}


class ImpersonationHandler(
                            identityEndpoint: String,
                            akkaServiceClient: AkkaServiceClient,
                            traceId: Option[String])
  extends AbstractFilterLogicHandler with LazyLogging {

  final def getAdminToken(adminUsername: String, adminPassword: String): Try[String] = {
    //authenticate, or get the admin token
    val authenticationPayload = Json.obj(
      "auth" -> Json.obj(
        "passwordCredentials" -> Json.obj(
          "username" -> adminUsername,
          "password" -> adminPassword
        )
      )
    )

    val akkaResponse = Try(akkaServiceClient.post(ImpersonationHandler.ADMIN_TOKEN_KEY,
      s"$identityEndpoint${ImpersonationHandler.TOKEN_ENDPOINT}",
      (Map(CommonHttpHeader.ACCEPT.toString -> MediaType.APPLICATION_JSON)
        ++ traceId.map(CommonHttpHeader.TRACE_GUID.toString -> _)).asJava,
      Json.stringify(authenticationPayload),
      MediaType.APPLICATION_JSON_TYPE
    ))

    akkaResponse match {
      case Success(serviceClientResponse) =>
        if(Option(serviceClientResponse).isDefined) {
          serviceClientResponse.getStatus match {
            case statusCode if statusCode >= 200 && statusCode < 300 =>
              val jsonResponse = Source.fromInputStream(serviceClientResponse.getData).getLines().mkString("")
              val json = Json.parse(jsonResponse)
              Try(Success((json \ "access" \ "token" \ "id").as[String])) match {
                case Success(s) => s
                case Failure(f) =>
                  Failure(IdentityCommunicationException("Token not found in identity response during admin authentication", f))
              }
            case HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE | ImpersonationHandler.SC_TOO_MANY_REQUESTS =>
              Failure(OverLimitException(ImpersonationHandler.buildRetryValue(serviceClientResponse), "Rate limited when getting admin token"))
            case statusCode if statusCode >= 500 =>
              Failure(IdentityCommunicationException("Identity Service not available to get admin token"))
            case _ => Failure(IdentityResponseProcessingException("Unable to successfully get admin token from Identity"))
          }
        } else {
          Failure(IdentityResponseProcessingException("Unable to successfully get admin token from Identity"))
        }
      case Failure(x) => Failure(IdentityResponseProcessingException("Failure communicating with identity during admin authentication", x))
    }
  }


  final def getImpersonationToken(userName: String, expirationTtl: Int, validatingToken: String): Try[ImpersonationHandler.ImpersonationToken] = {
    logger.trace(s"Retrieve impersonation token from identity")
    //authenticate, or get the admin token
    val impersonationPayload = Json.obj(
      "RAX-AUTH:impersonation" -> Json.obj(
        "user" -> Json.obj(
          "username" -> userName
        ),
        "expire-in-seconds" -> expirationTtl
      )
    )

    val akkaResponse = Try(akkaServiceClient.post(ImpersonationHandler.IMPERSONATION_TOKEN_KEY,
      s"$identityEndpoint${ImpersonationHandler.IMPERSONATION_ENDPOINT}",
      (Map(CommonHttpHeader.AUTH_TOKEN.toString -> validatingToken,
        CommonHttpHeader.ACCEPT.toString -> MediaType.APPLICATION_JSON)
        ++ traceId.map(CommonHttpHeader.TRACE_GUID.toString -> _)).asJava,
      Json.stringify(impersonationPayload),
      MediaType.APPLICATION_JSON_TYPE
    ))

    akkaResponse match {
      case Success(serviceClientResponse) =>
        if(Option(serviceClientResponse).isDefined) {
          logger.trace(s"Response code from identity is ${serviceClientResponse.getStatus}")
          serviceClientResponse.getStatus match {
            case statusCode if statusCode >= 200 && statusCode < 300 =>
              val jsonResponse = Source.fromInputStream(serviceClientResponse.getData).getLines().mkString("")
              try {
                val json = Json.parse(jsonResponse)
                //Have to convert it to a vector, because List isn't serializeable in 2.10
                val expirationDate = ImpersonationHandler.iso8601ToRfc1123((json \ "access" \ "token" \ "expires").as[String])
                val token = (json \ "access" \ "token" \ "id").as[String]
                val impersonationToken = ImpersonationHandler.ImpersonationToken(expirationDate, token)
                Success(impersonationToken)
              } catch {
                case oops@(_: JsResultException | _: JsonProcessingException) =>
                  Failure(IdentityCommunicationException("Unable to parse JSON from identity impersonate token response", oops))
              }
            case HttpServletResponse.SC_NOT_FOUND =>
              Failure(UserNotFoundException(s"Unable to find $userName in Identity."))
            case HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE | ImpersonationHandler.SC_TOO_MANY_REQUESTS =>
              Failure(OverLimitException(ImpersonationHandler.buildRetryValue(serviceClientResponse), "Rate limited when getting impersonation token"))
            case HttpServletResponse.SC_UNAUTHORIZED =>
              Failure(AdminTokenUnauthorizedException("Unable to authenticate your admin user"))
            case statusCode if statusCode >= 500 =>
              Failure(IdentityCommunicationException("Identity Service not available to get impersonation token"))
            case _ => Failure(IdentityResponseProcessingException("Unable to successfully get impersonation token from Identity"))
          }
        } else {
          Failure(IdentityResponseProcessingException("Unable to successfully get impersonation token from Identity"))
        }
      case Failure(x) => Failure(IdentityResponseProcessingException("Failure communicating with identity during impersonation token retrieval", x))
    }
  }
}

object ImpersonationHandler {
  final val SC_TOO_MANY_REQUESTS = 429
  final val TOKEN_ENDPOINT = "/tokens"
  final val IMPERSONATION_ENDPOINT = "/RAX-AUTH/impersonation-tokens"
  final val ADMIN_TOKEN_KEY = "IDENTITY:V2:ADMIN_TOKEN"
  final val IMPERSONATION_TOKEN_KEY = "IDENTITY:V2:IMPERSONATION_TOKEN"
  final val TOKEN_KEY_PREFIX = "IDENTITY:V2:TOKEN:"
  final val IMPERSONATION_KEY_PREFIX = "IDENTITY:V2:IMPERSONATION_TOKEN:"

  def iso8601ToRfc1123(iso: String) = {
    val dateTime = ISODateTimeFormat.dateTimeParser().parseDateTime(iso)
    DateUtils.formatDate(dateTime.toDate)
  }

  def buildRetryValue(response: ServiceClientResponse) = {
    if(Option(response.getHeaders).isDefined){
      response.getHeaders.find(header => HttpHeaders.RETRY_AFTER.equalsIgnoreCase(header.getName)) match {
        case Some(retryValue) => retryValue.getValue
        case _ =>
          val retryCalendar: Calendar = new GregorianCalendar
          retryCalendar.add(Calendar.SECOND, 5)
          DateUtils.formatDate(retryCalendar.getTime)
      }
    } else {
      "Retry-after header not specified"
    }
  }

  trait IdentityException


  case class ImpersonationToken(expirationDate: String,
                        token: String)

  case class AdminTokenUnauthorizedException(message: String, cause: Throwable = null) extends Exception(message, cause) with IdentityException

  case class IdentityAdminTokenException(message: String, cause: Throwable = null) extends Exception(message, cause) with IdentityException

  case class IdentityCommunicationException(message: String, cause: Throwable = null) extends Exception(message, cause) with IdentityException

  case class IdentityResponseProcessingException(message: String, cause: Throwable = null) extends Exception(message, cause) with IdentityException

  case class UserNotFoundException(message: String, cause: Throwable = null) extends Exception(message, cause) with IdentityException

  case class OverLimitException(retryAfter: String, message: String, cause: Throwable = null) extends Exception(message, cause) with IdentityException

}
