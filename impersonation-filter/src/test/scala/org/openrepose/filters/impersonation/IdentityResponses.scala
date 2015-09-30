package org.openrepose.filters


import org.joda.time.DateTime
import org.joda.time.format.ISODateTimeFormat

import scala.io.Source

trait IdentityResponses {

  protected final val VALID_TOKEN = "validToken"
  protected final val VALID_USER = "validUser"

  def tokenDateFormat(dateTime:DateTime): String = {
    ISODateTimeFormat.dateTime().print(dateTime)
  }

  def adminAuthenticationTokenResponse(token: String = "glibglob",
                                       expires: DateTime = DateTime.now()): String = {
    Source.fromURL(getClass.getResource("/payloads/validateTokenResponse.json")).getLines.map(in => {
        in.replaceAll("token_replacement", token).replaceAll("formattedTime_replacement", tokenDateFormat(expires))
      //in
     }
     ).mkString("\n")
  }

  def impersonateTokenResponse(token: String = VALID_TOKEN, expires: DateTime = DateTime.now().plusDays(1)): String = {

    Source.fromURL(getClass.getResource("/payloads/impersonationResponse.json")).getLines.map(in => {
      in.replaceAll("token_replacement", token).replaceAll("expiryTime_replacement", tokenDateFormat(expires))
    }
    ).mkString("\n")
  }
}
