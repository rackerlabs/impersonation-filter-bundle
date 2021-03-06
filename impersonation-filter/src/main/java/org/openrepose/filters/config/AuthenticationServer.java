//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.1-646 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.09.21 at 02:55:30 PM CDT 
//


package org.openrepose.filters.config;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * 
 * <pre>
 * &lt;?xml version="1.0" encoding="UTF-8"?&gt;&lt;html:p xmlns:html="http://www.w3.org/1999/xhtml" xmlns:impersonation="http://docs.openrepose.org/repose/impersonation/v1.0" xmlns:xs="http://www.w3.org/2001/XMLSchema"&gt;Describes an identity endpoint&lt;/html:p&gt;
 * </pre>
 * 
 *             
 * 
 * <p>Java class for AuthenticationServer complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AuthenticationServer">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;attribute name="username" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="password" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="tenantId" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="href" use="required" type="{http://www.w3.org/2001/XMLSchema}anyURI" />
 *       &lt;attribute name="impersonation-ttl" type="{http://docs.openrepose.org/repose/impersonation/v1.0}intGTEZero" default="300" />
 *       &lt;attribute name="connectionPoolId" type="{http://www.w3.org/2001/XMLSchema}string" default="impersonation-default" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AuthenticationServer")
public class AuthenticationServer {

    @XmlAttribute(required = true)
    protected String username;
    @XmlAttribute(required = true)
    protected String password;
    @XmlAttribute
    protected String tenantId;
    @XmlAttribute(required = true)
    @XmlSchemaType(name = "anyURI")
    protected String href;
    @XmlAttribute(name = "impersonation-ttl")
    protected Integer impersonationTtl;
    @XmlAttribute
    protected String connectionPoolId;

    /**
     * Gets the value of the username property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets the value of the username property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUsername(String value) {
        this.username = value;
    }

    /**
     * Gets the value of the password property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPassword() {
        return password;
    }

    /**
     * Sets the value of the password property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPassword(String value) {
        this.password = value;
    }

    /**
     * Gets the value of the tenantId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTenantId() {
        return tenantId;
    }

    /**
     * Sets the value of the tenantId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTenantId(String value) {
        this.tenantId = value;
    }

    /**
     * Gets the value of the href property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getHref() {
        return href;
    }

    /**
     * Sets the value of the href property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setHref(String value) {
        this.href = value;
    }

    /**
     * Gets the value of the impersonationTtl property.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public int getImpersonationTtl() {
        if (impersonationTtl == null) {
            return  300;
        } else {
            return impersonationTtl;
        }
    }

    /**
     * Sets the value of the impersonationTtl property.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setImpersonationTtl(Integer value) {
        this.impersonationTtl = value;
    }

    /**
     * Gets the value of the connectionPoolId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getConnectionPoolId() {
        if (connectionPoolId == null) {
            return "impersonation-default";
        } else {
            return connectionPoolId;
        }
    }

    /**
     * Sets the value of the connectionPoolId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setConnectionPoolId(String value) {
        this.connectionPoolId = value;
    }

}
