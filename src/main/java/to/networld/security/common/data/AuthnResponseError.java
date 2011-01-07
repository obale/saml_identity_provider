/**
 * identity_provider - to.networld.security.common.data
 *
 * Copyright (C) 2010 by Networld Project
 * Written by Alex Oberhauser <oberhauseralex@networld.to>
 * All Rights Reserved
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>
 */

package to.networld.security.common.data;

import java.util.UUID;
import java.util.Vector;

import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

import org.dom4j.Element;
import org.dom4j.QName;

import to.networld.security.common.DateHelper;

/**
 * @author Alex Oberhauser
 */
public class AuthnResponseError extends GenericSAMLMessage {
	/**
	 * Exclusive the SUCCESS code, because than the 
	 * AuthnResponse class should be used.
	 * 
	 * Codes are from the SAML2-Core specification.
	 */
	public enum CODE {
		REQUESTER, 			// Requester Error
		RESPONDER,
		VERSION_MISMATCH,
		AUTHN_FAILED,
		INVALID_ATTR_NAME_OR_VALUE,
		INVALID_NAME_ID_POLICY,
		NO_AUTHN_CONTEXT,
		NO_AVAILABLE_IDP,
		NO_PASSIV,
		NO_SUPPORTED_IDP,
		PARTIAL_LOGOUT,
		PROXY_COUNT_EXCEEDED,
		REQUEST_DENIED,
		REQUEST_UNSUPPORTED,
		REQUEST_VERSION_DEPRECATED,
		REQUEST_VERSION_TOO_HIGH,
		REQUEST_VERSION_TOO_LOW,
		RESOURCE_NOT_RECOGNIZED,
		TOO_MANY_RESPONSE,
		UNKNOWN_ATTR_PROFILE,
		UNKNOWN_PRINCIPAL,
		UNSUPPORTED_BINDING
	}
	
	private Vector<String> statusVector = new Vector<String>();
	
	public AuthnResponseError(CODE _code, String _issuer, String _destinationIRI, String _requestID) {
		this.initStatusVector();
		Element authnResponse = this.xmlDocument.addElement(new QName("Response", SAMLP_NS));
		authnResponse.add(SAML_NS);

		authnResponse.addAttribute("Destination", _destinationIRI);
		String id = UUID.randomUUID().toString();
		authnResponse.addAttribute("ID", id);
		authnResponse.addAttribute("InResponseTo", _requestID);
		authnResponse.addAttribute("IssueInstant", DateHelper.getCurrentDate());
		authnResponse.addAttribute("Version", "2.0");
		
		Element issuer = authnResponse.addElement(new QName("Issuer", SAML_NS));
		issuer.setText(_issuer);
		
		Element status = authnResponse.addElement(new QName("Status", SAMLP_NS));
		Element statusCode = status.addElement(new QName("StatusCode", SAMLP_NS));
		statusCode.addAttribute("Value", this.statusVector.get(_code.ordinal()));
	}
	
	private void initStatusVector() {
		String prefix = "urn:oasis:names:tc:SAML:2.0:status:";
		this.statusVector.add(prefix + "Requester");
		this.statusVector.add(prefix + "Responder");
		this.statusVector.add(prefix + "VersionMismatch");
		this.statusVector.add(prefix + "AuthnFailed");
		this.statusVector.add(prefix + "InvalidAttrNameOrValue");
		this.statusVector.add(prefix + "InvalidNameIDPolicy");
		this.statusVector.add(prefix + "NoAuthnContext");
		this.statusVector.add(prefix + "NoAvailableIDP");
		this.statusVector.add(prefix + "NoPassive");
		this.statusVector.add(prefix + "NoSupportedIDP");
		this.statusVector.add(prefix + "PartialLogout");
		this.statusVector.add(prefix + "ProxyCountExceeded");
		this.statusVector.add(prefix + "RequestDenied");
		this.statusVector.add(prefix + "RequestUnsupported");
		this.statusVector.add(prefix + "RequestVersionDeprecated");
		this.statusVector.add(prefix + "RequestVersionTooHigh");
		this.statusVector.add(prefix + "RequestVersionTooLow");
		this.statusVector.add(prefix + "ResourceNotRecognized");
		this.statusVector.add(prefix + "TooManyResponse");
		this.statusVector.add(prefix + "UnknownAttrProfile");
		this.statusVector.add(prefix + "UnknownPrincipal");
		this.statusVector.add(prefix + "UnsupportedBinding");
	}
	
	public String getStatus() { return this.getAttributeValue("/samlp:Response/samlp:Status/samlp:StatusCode", "Value"); }

	/**
	 * @see to.networld.security.common.data.GenericSAMLMessage#load(javax.xml.soap.SOAPMessage)
	 */
	@Override
	public void load(SOAPMessage soapMessage) throws SOAPException {
		// TODO Auto-generated method stub
	}

}
