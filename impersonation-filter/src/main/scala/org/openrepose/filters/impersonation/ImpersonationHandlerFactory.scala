package org.openrepose.filters.impersonation

import java.util

import org.openrepose.commons.config.manager.UpdateListener
import org.openrepose.core.filter.logic.AbstractConfiguredFilterHandlerFactory
import org.openrepose.filters.config.RackspaceImpersonation

/**
 * Created by dimi5963 on 9/21/15.
 */
class ImpersonationHandlerFactory extends AbstractConfiguredFilterHandlerFactory[ImpersonationHandler] {

  private var impersonationHandler: ImpersonationHandler = _

  override protected def buildHandler: ImpersonationHandler = {
    if (isInitialized) impersonationHandler
    else null
  }

  override protected def getListeners: util.Map[Class[_], UpdateListener[_]] = {
    val listenerMap = new util.HashMap[Class[_], UpdateListener[_]]()

    listenerMap.put(classOf[RackspaceImpersonation], new RackspaceImpersonationConfigurationListener())

    listenerMap
  }

  private class RackspaceImpersonationConfigurationListener extends UpdateListener[RackspaceImpersonation] {
    private var initialized = false

    def configurationUpdated(rackspaceImpersonationConfigObject: RackspaceImpersonation) {
      impersonationHandler = new ImpersonationHandler(rackspaceImpersonationConfigObject)
      initialized = true
    }

    override def isInitialized: Boolean = {
      initialized
    }
  }

}