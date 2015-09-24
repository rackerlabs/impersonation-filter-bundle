/*
 * _=_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_=
 * Repose - external
 * _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
 * Copyright (C) 2010 - 2015 Rackspace US, Inc.
 * _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_=_
 */
package org.openrepose.filters.impersonation

import java.util.concurrent.TimeUnit
import javax.inject.{Inject, Named}
import javax.servlet._
import javax.servlet.http.{HttpServletResponse, HttpServletRequest}
import org.apache.http.HttpHeaders
import org.openrepose.commons.config.manager.UpdateListener
import org.openrepose.commons.utils.http.{OpenStackServiceHeader, CommonHttpHeader}
import org.openrepose.commons.utils.servlet.http.MutableHttpServletRequest
import org.openrepose.core.filter.FilterConfigHelper
import org.openrepose.core.services.config.ConfigurationService
import com.typesafe.scalalogging.slf4j.LazyLogging
import org.openrepose.core.services.datastore.{DatastoreService, Datastore}
import org.openrepose.core.services.serviceclient.akka.{AkkaServiceClientException, AkkaServiceClient}
import org.openrepose.core.systemmodel.SystemModel
import org.openrepose.filters.config.RackspaceImpersonation
import org.openrepose.filters.impersonation.ImpersonationHandler._
import org.apache.http.client.utils.DateUtils
import com.rackspace.httpdelegation.HttpDelegationManager


import scala.concurrent.TimeoutException
import scala.util.{Failure, Random, Success, Try}

class ImpersonationFilter @Inject()(configurationService: ConfigurationService,
                                    akkaServiceClient: AkkaServiceClient,
                                    datastoreService: DatastoreService)
  extends Filter with LazyLogging with HttpDelegationManager {

  private final val DEFAULT_CONFIG = "rackspace-impersonation.cfg.xml"
  private final val SYSTEM_MODEL_CONFIG = "system-model.cfg.xml"
  private var sendTraceHeader = true

  import ImpersonationFilter._

  private val datastore: Datastore = datastoreService.getDefaultDatastore

  private var impersonationConfig: RackspaceImpersonation = _
  private var impersonationConfigFile: String = _

  def isInitialized = SystemModelConfigListener.isInitialized && ImpersonationConfigListener .isInitialized

  override def init(filterConfig: FilterConfig): Unit = {
    //load configuration file
    impersonationConfigFile = new FilterConfigHelper(filterConfig).getFilterConfig(DEFAULT_CONFIG)
    logger.info(s"Initializing Rackspace Impersonation Filter using config $impersonationConfigFile")

    val xsdURL = getClass.getResource("/META-INF/schema/config/rackspace-impersonation.xsd")


    configurationService.subscribeTo(
      SYSTEM_MODEL_CONFIG,
      getClass.getResource("/META-INF/schema/system-model/system-model.xsd"),
      SystemModelConfigListener,
      classOf[SystemModel]
    )
    configurationService.subscribeTo(
      filterConfig.getFilterName,
      impersonationConfigFile,
      xsdURL,
      ImpersonationConfigListener,
      classOf[RackspaceImpersonation])
  }

  override def destroy(): Unit = {
    configurationService.unsubscribeFrom(impersonationConfigFile, ImpersonationConfigListener)
    configurationService.unsubscribeFrom(SYSTEM_MODEL_CONFIG, SystemModelConfigListener)
  }

  override def doFilter(servletRequest: ServletRequest, servletResponse: ServletResponse, chain: FilterChain): Unit = {
    /**
     * STATIC REFERENCE TO CONFIG
     */
    val config = impersonationConfig

    /**
     * DECLARE COMMON VALUES
     */
    lazy val request = MutableHttpServletRequest.wrap(servletRequest.asInstanceOf[HttpServletRequest])
    // Not using the mutable wrapper because it doesn't work properly at the moment, and
    // we don't need to modify the response from further down the chain
    lazy val response = servletResponse.asInstanceOf[HttpServletResponse]
    lazy val traceId = Option(request.getHeader(CommonHttpHeader.TRACE_GUID.toString)).filter(_ => sendTraceHeader)
    lazy val requestHandler = new ImpersonationHandler(
      impersonationConfig.getAuthenticationServer.getHref, akkaServiceClient, traceId)

    /**
     * BEGIN PROCESSING
     */
    if (!isInitialized) {
      logger.error("Rackspace Impersonation filter has not yet initialized")
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)
    } else {
      logger.debug("Rackspace Impersonation filter processing request...")

      /**
       * We have an auth token and admin token.  Let's figure out whether impersonation token exists
       * 1. Validate impersonation token in cache
       * 2. Doesn't exist?
       * 2a. Get admin token
       * 2b. Get auth token
       */

      val filterResult = {
        val processingResult =
          getUser flatMap { userName =>
            getImpersonationToken(getAdminToken, userName)
          }

        processingResult match {
          case Success(_) => Pass
          case Failure(e: UserNotFoundException) => Reject(HttpServletResponse.SC_UNAUTHORIZED, Some(e.getMessage))
          case Failure(e: MissingAuthTokenException) => Reject(HttpServletResponse.SC_UNAUTHORIZED, Some(e.getMessage))
          case Failure(e: IdentityCommunicationException) => Reject(HttpServletResponse.SC_BAD_GATEWAY, Some(e.getMessage))
          case Failure(e: OverLimitException) =>
            response.addHeader(HttpHeaders.RETRY_AFTER, e.retryAfter)
            Reject(HttpServletResponse.SC_SERVICE_UNAVAILABLE, Some(e.getMessage))
          //case Failure(e) if e.getCause.isInstanceOf[AkkaServiceClientException] && e.getCause.getCause.isInstanceOf[TimeoutException] =>
          //  Reject(HttpServletResponse.SC_GATEWAY_TIMEOUT, Some(s"Call timed out: ${e.getMessage}"))
          case Failure(e) => Reject(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, Some(e.getMessage))
        }
      }

      filterResult match {
        case Pass =>
          logger.trace("Processing completed, passing to next filter or service")
          chain.doFilter(request, response)
        case Reject(statusCode, message) =>
          Option(config.getDelegating) match {
            case Some(delegating) =>
              logger.debug(s"Delegating with status $statusCode caused by: ${message.getOrElse("unspecified")}")
              val delegationHeaders = buildDelegationHeaders(statusCode,
                "rackspace-impersonation",
                message.getOrElse("Failure in the Rackspace impersonation filter").replace("\n", " "),
                delegating.getQuality)

              delegationHeaders foreach { case (key, values) =>
                values foreach { value =>
                  request.addHeader(key, value)
                }
              }
              chain.doFilter(request, response)
            case None =>
              logger.debug(s"Rejecting with status $statusCode")

              message match {
                case Some(m) =>
                  logger.debug(s"Rejection message: $m")
                  response.sendError(statusCode, m)
                case None => response.sendError(statusCode)
              }
          }
      }
    }

    def updateTokenHeader(impersonationToken: ImpersonationToken): Unit = {
      if(request.getHeader(CommonHttpHeader.AUTH_TOKEN.toString) != null)
        request.replaceHeader(CommonHttpHeader.AUTH_TOKEN.toString, impersonationToken.token)
      else
        request.addHeader(CommonHttpHeader.AUTH_TOKEN.toString, impersonationToken.token)

      if(request.getHeader(OpenStackServiceHeader.X_EXPIRATION.toString) != null)
        request.replaceHeader(OpenStackServiceHeader.X_EXPIRATION.toString, impersonationToken.expirationDate)
      else
        request.addHeader(OpenStackServiceHeader.X_EXPIRATION.toString, impersonationToken.expirationDate)
    }


    def getUser: Try[String] = {
      logger.trace("Getting the x-user-name header value")

      Option(request.getHeader(OpenStackServiceHeader.USER_NAME.toString)) match {
        case Some(user) => Success(user)
        case None => Failure(MissingAuthTokenException("X-User-Name header not found"))
      }
    }

    def getAdminToken(force: Boolean): Try[String] = {
      logger.trace("Getting an admin token with the configured credentials")

      // If force is true, clear the cache and acquire a new token
      if (force) datastore.remove(ImpersonationHandler.ADMIN_TOKEN_KEY)

      Option(datastore.get(ImpersonationHandler.ADMIN_TOKEN_KEY).asInstanceOf[String]) match {
        case Some(cachedAdminToken) => Success(cachedAdminToken)
        case None =>
          requestHandler.getAdminToken(config.getAuthenticationServer.getUsername, config.getAuthenticationServer.getPassword) match {
            case Success(adminToken) =>
              datastore.put(ImpersonationHandler.ADMIN_TOKEN_KEY, adminToken)
              Success(adminToken)
            case f: Failure[_] => f
          }
      }
    }


    def getImpersonationToken(getAdminToken: Boolean => Try[String], userName: String): Try[ImpersonationHandler.ImpersonationToken] = {
      logger.trace(s"Retrieve impersonation token for: $userName")

      //let's see if we have an impersonation token in cache
      Option(datastore.get(s"${ImpersonationHandler.IMPERSONATION_KEY_PREFIX}$userName").asInstanceOf[ImpersonationHandler.ImpersonationToken]) match {
        case Some(cachedImpersonationToken) =>
          updateTokenHeader(cachedImpersonationToken)
          Success(cachedImpersonationToken)
        case None =>
          //get some data here
          val impersonationTtl = config.getAuthenticationServer.getImpersonationTtl
          getAdminToken(false) flatMap { validatingToken =>
            requestHandler.getImpersonationToken(userName, impersonationTtl, validatingToken) recoverWith {
              case _: AdminTokenUnauthorizedException =>
                // Force acquiring of the admin token, and call the validation function again (retry once)
                getAdminToken(true) match {
                  case Success(newValidatingToken) => requestHandler.getImpersonationToken(userName, impersonationTtl, newValidatingToken)
                  case Failure(x) => Failure(IdentityAdminTokenException("Unable to reacquire admin token", x))
                }
            } cacheOnSuccess { impersonationToken =>
              val timeToLive = getTtl(config.getAuthenticationServer.getImpersonationTtl,
                Some(impersonationToken))
              timeToLive foreach { ttl =>
                datastore.put(s"${ImpersonationHandler.IMPERSONATION_KEY_PREFIX}$userName", impersonationToken, ttl, TimeUnit.SECONDS)
              }
              updateTokenHeader(impersonationToken)
            }
          }
      }
    }
  }


  def getTtl(baseTtl: Int, tokenOption: Option[ImpersonationToken] = None): Option[Int] = {
    def safeLongToInt(l: Long): Int = math.min(l, Int.MaxValue).toInt

    val tokenTtl = {
      tokenOption match {
        case Some(token) =>
          // If a token has been provided, calculate the TTL
          val tokenExpiration = DateUtils.parseDate(token.expirationDate).getTime - System.currentTimeMillis()

          if (tokenExpiration < 1) {
            // If the token has already expired or set to 0, don't cache
            None
          } else {
            val tokenExpirationSeconds = tokenExpiration / 1000

            if (tokenExpirationSeconds > Int.MaxValue) {
              logger.warn("Token expiration time exceeds maximum possible value -- setting to maximum possible value")
            }
            // Cache for the token TTL after converting from milliseconds to seconds
            Some(safeLongToInt(tokenExpirationSeconds))
          }
        case None =>
          // If a token has not been provided, don't cache
          None
      }
    }

    val configuredTtl = {
      if (baseTtl < 0) {
        // Caching is disabled by configuration
        None
      } else  {
        // Caching is set to forever
        Some(baseTtl)
      }
    }

    (tokenTtl, configuredTtl) match {
      case (Some(tttl), None) => None
      case (Some(tttl), Some(cttl)) => Some(Math.min(tttl, cttl))
      case (None, Some(cttl)) => None
      case (None, None) => None
    }
  }


  object SystemModelConfigListener extends UpdateListener[SystemModel] {
    private var initialized = false

    override def configurationUpdated(configurationObject: SystemModel): Unit = {
      sendTraceHeader = configurationObject.isTracingHeader
      initialized = true
    }

    override def isInitialized: Boolean = initialized
  }

  object ImpersonationConfigListener extends UpdateListener[RackspaceImpersonation] {
    private var initialized = false

    override def configurationUpdated(configurationObject: RackspaceImpersonation): Unit = {
      // Removes an extra slash at the end of the URI if applicable
      impersonationConfig = configurationObject
      val serviceUri = impersonationConfig.getAuthenticationServer.getHref
      impersonationConfig.getAuthenticationServer.setHref(serviceUri.stripSuffix("/"))

      initialized = true
    }

    override def isInitialized: Boolean = initialized
  }

}

object ImpersonationFilter {

  case class MissingAuthTokenException(message: String, cause: Throwable = null) extends Exception(message, cause)

  implicit def toCachingTry[T](tryToWrap: Try[T]): CachingTry[T] = new CachingTry(tryToWrap)

  class CachingTry[T](wrappedTry: Try[T]) {
    def cacheOnSuccess(cachingFunction: T => Unit): Try[T] = {
      wrappedTry match {
        case Success(it) =>
          cachingFunction(it)
          wrappedTry
        case f: Failure[_] => f
      }
    }
  }

  sealed trait ImpersonationResult

  object Pass extends ImpersonationResult

  case class Reject(status: Int, message: Option[String] = None) extends ImpersonationResult


}

