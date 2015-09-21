package org.openrepose.filters.impersonation

import javax.servlet.http.HttpServletRequest

import com.typesafe.scalalogging.slf4j.LazyLogging
import org.openrepose.commons.utils.servlet.http.ReadableHttpServletResponse
import org.openrepose.core.filter.logic.FilterDirector
import org.openrepose.core.filter.logic.common.AbstractFilterLogicHandler
import org.openrepose.core.filter.logic.impl.FilterDirectorImpl
import org.openrepose.filters.config.RackspaceImpersonation

class ImpersonationHandler(config: RackspaceImpersonation) extends AbstractFilterLogicHandler with LazyLogging {

  override def handleRequest(request: HttpServletRequest, response: ReadableHttpServletResponse): FilterDirector = {
    val filterDirector = new FilterDirectorImpl()
    val headerManager = filterDirector.requestHeaderManager()

    //go get some data here

    filterDirector
  }
}
