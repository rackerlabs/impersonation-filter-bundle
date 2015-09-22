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

import javax.inject.{Inject, Named}
import javax.servlet._
import javax.servlet.http.{HttpServletResponse, HttpServletRequest}
import javax.ws.rs.core.HttpHeaders
import org.openrepose.commons.config.manager.UpdateListener
import org.openrepose.commons.utils.http.CommonHttpHeader
import org.openrepose.commons.utils.servlet.http.MutableHttpServletRequest
import org.openrepose.core.filter.FilterConfigHelper
import org.openrepose.core.services.config.ConfigurationService
import com.typesafe.scalalogging.slf4j.LazyLogging
import org.openrepose.core.services.datastore.{DatastoreService, Datastore}
import org.openrepose.core.services.serviceclient.akka.{AkkaServiceClientException, AkkaServiceClient}
import org.openrepose.core.systemmodel.SystemModel
import org.openrepose.filters.config.RackspaceImpersonation
import org.openrepose.filters.impersonation.ImpersonationFilter.{Reject, Pass, MissingAuthTokenException}
import org.openrepose.filters.impersonation.ImpersonationHandler.{IdentityResponseProcessingException, OverLimitException, IdentityCommunicationException}


import scala.concurrent.TimeoutException
import scala.util.{Failure, Random, Success, Try}

class ImpersonationFilter @Inject()(configurationService: ConfigurationService,
                                    akkaServiceClient: AkkaServiceClient,
                                    datastoreService: DatastoreService)
  extends Filter with LazyLogging {

  private final val DEFAULT_CONFIG = "rackspace-impersonation.cfg.xml"
  private final val SYSTEM_MODEL_CONFIG = "system-model.cfg.xml"
  private var sendTraceHeader = true

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
       *  2a. Get admin token
       *  2b. Get auth token
       */

      val filterResult = {
        val processingResult =
          getAuthToken flatMap { authToken =>
            getImpersonationToken(getAdminToken, authToken)
          }

        processingResult match {
          case Success(_) => Pass
          case Failure(e: MissingAuthTokenException) => Reject(HttpServletResponse.SC_UNAUTHORIZED, Some(e.getMessage))
          case Failure(e: IdentityCommunicationException) => Reject(HttpServletResponse.SC_BAD_GATEWAY, Some(e.getMessage))
          case Failure(e: OverLimitException) =>
            response.addHeader(HttpHeaders.RETRY_AFTER, e.retryAfter)
            Reject(HttpServletResponse.SC_SERVICE_UNAVAILABLE, Some(e.getMessage))
          case Failure(e) if e.getCause.isInstanceOf[AkkaServiceClientException] && e.getCause.getCause.isInstanceOf[TimeoutException] =>
            Reject(HttpServletResponse.SC_GATEWAY_TIMEOUT, Some(s"Call timed out: ${e.getMessage}"))
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
              logger.debug("Not delegating at the moment.  Maybe later?")
              /*
              val delegationHeaders = buildDelegationHeaders(statusCode,
                "keystone-v2",
                message.getOrElse("Failure in the Keystone v2 filter").replace("\n", " "),
                delegating.getQuality)

              delegationHeaders foreach { case (key, values) =>
                values foreach { value =>
                  request.addHeader(key, value)
                }
              }
              chain.doFilter(request, response)

              logger.trace(s"Processing response with status code: $statusCode")
              */
              logger.debug(s"Rejecting with status $statusCode")

              message match {
                case Some(m) =>
                  logger.debug(s"Rejection message: $m")
                  response.sendError(statusCode, m)
                case None => response.sendError(statusCode)
              }
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


    def getAuthToken: Try[String] = {
      logger.trace("Getting the x-auth-token header value")

      Option(request.getHeader(CommonHttpHeader.AUTH_TOKEN)) match {
        case Some(token) => Success(token)
        case None => Failure(MissingAuthTokenException("X-Auth-Token header not found"))
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


    def getImpersonationToken(getAdminToken: Boolean => Try[String], authToken: String): Try[ImpersonationHandler.ImpersonationToken] = {
      logger.trace(s"Retrieve impersonation token for: $authToken")

      //let's see if we have an impersonation token in cache
      Option(datastore.get(s"$ImpersonationHandler.IMPERSONATION_KEY_PREFIX$authToken").asInstanceOf[ImpersonationHandler.ImpersonationToken]) match {
        case Some(cachedImpersonationToken) => Success(cachedImpersonationToken)
        case None =>
          //get some data here
          getAdminToken(false) flatMap { validatingToken =>
            requestHandler.getImpersonationToken(validatingToken, authToken) recoverWith {
              case _: AdminTokenUnauthorizedException =>
                // Force acquiring of the admin token, and call the validation function again (retry once)
                getAdminToken(true) match {
                  case Success(newValidatingToken) => requestHandler.validateToken(newValidatingToken, authToken)
                  case Failure(x) => Failure(IdentityAdminTokenException("Unable to reacquire admin token", x))
                }
            } cacheOnSuccess { validToken =>
              val cacheSettings = config.getCache.getTimeouts
              val timeToLive = getTtl(cacheSettings.getToken,
                cacheSettings.getVariability,
                Some(validToken))
              timeToLive foreach { ttl =>
                datastore.put(s"$TOKEN_KEY_PREFIX$authToken", validToken, ttl, TimeUnit.SECONDS)
              }
            }
          }

      }
      map
      } { validationResult =>
        Success(validationResult)
      } getOrElse {

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
      val serviceUri = impersonationConfig.getAuthenticationServer.getHref
      impersonationConfig.getAuthenticationServer.setHref(serviceUri.stripSuffix("/"))

      initialized = true
    }

    override def isInitialized: Boolean = initialized
  }

}

object ImpersonationFilter {

  case class MissingAuthTokenException(message: String, cause: Throwable = null) extends Exception(message, cause)

  sealed trait ImpersonationResult

  object Pass extends ImpersonationResult

  case class Reject(status: Int, message: Option[String] = None) extends ImpersonationResult


}

