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

import java.util.Iterator;
import java.util.UUID;

import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPBodyElement;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

import org.dom4j.Element;
import org.dom4j.QName;

import to.networld.security.common.DateHelper;
import to.networld.security.common.saml.ConstantHandler;
import to.networld.security.common.saml.NameIDFormat.ID_FORMAT;

/**
 * @author Alex Oberhauser
 */
public class AuthnRequest extends GenericSAMLMessage {	
	
	public AuthnRequest() {}
	
	public AuthnRequest(String _issuer, ID_FORMAT _nameIDFormat) {
		this.writeAuthnRequest(UUID.randomUUID().toString(),
				DateHelper.getCurrentDate(), 
				_issuer,
				ConstantHandler.getInstance().getNameIDFormat(_nameIDFormat),
				"2.0", "true", "0", "0");
	}

	private void writeAuthnRequest(String _id,
			String _issueInstant,
			String _issuer,
			String _nameIDFormat,
			String _version,
			String _allowCreate,
			String _assertionConsumerServiceIndex,
			String _attributeConsumingServiceIndex) {
		Element authnRequestNode = this.xmlDocument.addElement(new QName("AuthnRequest", SAMLP_NS));
		authnRequestNode.add(SAML_NS);
		
		authnRequestNode.addAttribute("ID", _id);
		authnRequestNode.addAttribute("Version", _version);
		authnRequestNode.addAttribute("IssueInstant", _issueInstant);
		authnRequestNode.addAttribute("AssertionConsumerServiceIndex", _assertionConsumerServiceIndex);
		authnRequestNode.addAttribute("AttributeConsumingServiceIndex", _attributeConsumingServiceIndex);
		
		Element issuerNode = authnRequestNode.addElement(new QName("Issuer", SAML_NS));
		issuerNode.setText(_issuer);
		
		Element namedIDPolicyNode = authnRequestNode.addElement(new QName("NameIDPolicy", SAMLP_NS));
		namedIDPolicyNode.addAttribute("AllowCreate", _allowCreate);
		namedIDPolicyNode.addAttribute("Format", _nameIDFormat);
	}
	
	public String getRequestID() { return this.getAttributeValue("/samlp:AuthnRequest", "ID"); }
	
	public String getIssuer() { return this.getElementValue("/samlp:AuthnRequest/saml:Issuer"); }
	public String getIssueInstant() { return this.getAttributeValue("/samlp:AuthnRequest", "IssueInstant"); }
	
	public String getNameIDFormat() { return this.getAttributeValue("/samlp:AuthnRequest/samlp:NameIDPolicy", "Format"); }
	public String getNameIDAllowCreate() { return this.getAttributeValue("/samlp:AuthnRequest/samlp:NameIDPolicy", "AllowCreate"); }

	/**
	 * @see to.networld.security.common.data.GenericSAMLMessage#load(javax.xml.soap.SOAPMessage)
	 */
	@Override
	public void load(SOAPMessage _soapMessage) throws SOAPException {
		SOAPBody body = _soapMessage.getSOAPBody();
		
		String requestID = "";
		String version = "2.0";
		String issueInstant = "";
		String issuerName = "";
		String allowCreate = "true";
		String format = "";
		String assertionConsumerServiceIndex = "0";
		String attributeConsumingServiceIndex = "0";
		
		Iterator<?> iter = body.getChildElements(new javax.xml.namespace.QName("urn:oasis:names:tc:SAML:2.0:protocol", "AuthnRequest"));
		if ( iter.hasNext() ) {
			SOAPBodyElement authnRequest = (SOAPBodyElement) iter.next();

			requestID = authnRequest.getAttribute("ID");
			version = authnRequest.getAttribute("Version");
			issueInstant = authnRequest.getAttribute("IssueInstant");
			assertionConsumerServiceIndex = authnRequest.getAttribute("AssertionConsumerServiceIndex");
			attributeConsumingServiceIndex = authnRequest.getAttribute("AttributeConsumingServiceIndex");

			Iterator<?> iterIssuer = authnRequest.getChildElements(new javax.xml.namespace.QName("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer"));
			if ( iterIssuer.hasNext() ) {
				SOAPElement issuer = (SOAPElement) iterIssuer.next();
				issuerName = issuer.getTextContent();
			}

			Iterator<?> iterNameIDPolicy = authnRequest.getChildElements(new javax.xml.namespace.QName("urn:oasis:names:tc:SAML:2.0:protocol", "NameIDPolicy"));
			if ( iterNameIDPolicy.hasNext() ) {
				SOAPElement nameIDPolicy = (SOAPElement) iterNameIDPolicy.next();
				allowCreate = nameIDPolicy.getAttribute("AllowCreate");
				format = nameIDPolicy.getAttribute("Format");
			}	
		}
		this.writeAuthnRequest(requestID, issueInstant, issuerName, format, version, allowCreate, assertionConsumerServiceIndex, attributeConsumingServiceIndex);
	}
}
