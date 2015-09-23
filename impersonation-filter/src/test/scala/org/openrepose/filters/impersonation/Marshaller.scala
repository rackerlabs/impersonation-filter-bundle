package org.openrepose.filters.impersonation

import java.net.URL
import java.nio.charset.StandardCharsets

import org.openrepose.commons.config.parser.jaxb.JaxbConfigurationParser
import org.openrepose.commons.config.resource.ConfigurationResource
import org.openrepose.commons.config.resource.impl.{ByteArrayConfigurationResource, BufferedURLConfigurationResource}
import org.openrepose.core.systemmodel.SystemModel
import org.openrepose.filters.config.RackspaceImpersonation

import scala.reflect.ClassTag

object Marshaller {

  val systemModelXSD = getClass.getResource("/META-INF/schema/system-model/system-model.xsd")
  val rackspaceImpersonationXSD = getClass.getResource("/META-INF/schema/config/rackspace-impersonation.xsd")


  def systemModel(resource: String): SystemModel = {
    configResource[SystemModel](new BufferedURLConfigurationResource(this.getClass.getResource(resource)), systemModelXSD)
  }

  def configResource[T: ClassTag](configResource: ConfigurationResource, xsdURL: URL): T = {
    import scala.reflect._
    val ct: ClassTag[T] = classTag[T]
    val parser = JaxbConfigurationParser.getXmlConfigurationParser(
      ct.runtimeClass.asInstanceOf[Class[T]],
      xsdURL,
      this.getClass.getClassLoader)

    parser.read(configResource)
  }

  def impersonationConfig(resource: String): RackspaceImpersonation = {
    configResource[RackspaceImpersonation](new BufferedURLConfigurationResource(this.getClass.getResource(resource)), rackspaceImpersonationXSD)
  }

  def impersonationConfigFromString(content: String): RackspaceImpersonation = {
    configResource[RackspaceImpersonation](new ByteArrayConfigurationResource("rackspaceImpersonation", content.getBytes(StandardCharsets.UTF_8)), rackspaceImpersonationXSD)

  }
}