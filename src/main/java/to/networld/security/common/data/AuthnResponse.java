/**
 * identity_provider - to.networld.security.common.data
 *
 * Copyright (C) 2010 by Networld Project
 * Written by Alex Oberhauser <alexoberhauser@networld.to>
 * Written by Corneliu Valentin Stanciu <stanciucorneliu@networld.to>
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.UUID;

import org.dom4j.Element;
import org.dom4j.QName;
import org.dom4j.io.SAXReader;

import to.networld.security.common.DateHelper;
import to.networld.security.common.XMLSecurity;
import to.networld.security.common.saml.ConstantHandler;
import to.networld.security.common.saml.AuthnContextClasses.AUTH_METHOD;
import to.networld.security.common.saml.NameIDFormat.ID_FORMAT;

/**
 * @author Alex Oberhauser
 */
public class AuthnResponse extends GenericSAMLMessage {
	
	public AuthnResponse() {}
	
	public AuthnResponse(XMLSecurity _xmlsec, String _nameID, String _issuer, String _requestID, String _destinationIRI, String _audience, ID_FORMAT _format, AUTH_METHOD _classes) {
		ConstantHandler constHandler = ConstantHandler.getInstance();
		String currentDate = DateHelper.getCurrentDate();
		String futureDate = DateHelper.getFutureDate(10);
		
		Element authnResponse = this.xmlDocument.addElement(new QName("Response", SAMLP_NS));
		authnResponse.add(SAML_NS);

		authnResponse.addAttribute("Destination", _destinationIRI);
		String id = UUID.randomUUID().toString();
		authnResponse.addAttribute("ID", id);
		authnResponse.addAttribute("InResponseTo", _requestID);
		authnResponse.addAttribute("IssueInstant", currentDate);
		authnResponse.addAttribute("Version", "2.0");
		
		Element issuer = authnResponse.addElement(new QName("Issuer", SAML_NS));
		issuer.setText(_issuer);
		
		Element status = authnResponse.addElement(new QName("Status", SAMLP_NS));
		Element statusCode = status.addElement(new QName("StatusCode", SAMLP_NS));
		statusCode.addAttribute("Value", "urn:oasis:names:tc:SAML:2.0:status:Success");
		
		Element assertion = authnResponse.addElement(new QName("Assertion", SAML_NS));
		String assertionID = UUID.randomUUID().toString();
		assertion.addAttribute("ID", assertionID);
		assertion.addAttribute("Version", "2.0");
		assertion.addAttribute("IssueInstant", currentDate);
		
		Element assertionIssuer = assertion.addElement(new QName("Issuer", SAML_NS));
		assertionIssuer.setText(_issuer);
		
		Element assertionSubject = assertion.addElement(new QName("Subject", SAML_NS));
		
		Element assertionNameID = assertionSubject.addElement(new QName("NameID", SAML_NS));
		assertionNameID.addAttribute("Format", constHandler.getNameIDFormat(_format));
		assertionNameID.setText(_nameID);
		
		Element assertionSubjectConfirmation = assertionSubject.addElement(new QName("SubjectConfirmation", SAML_NS));
		assertionSubjectConfirmation.addAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer");
		
		Element assertionSubjectConfirmationData = assertionSubjectConfirmation.addElement(new QName("SubjectConfirmationData", SAML_NS));
		assertionSubjectConfirmationData.addAttribute("InResponseTo", _requestID);
		assertionSubjectConfirmationData.addAttribute("NotOnOrAfter", futureDate);
		assertionSubjectConfirmationData.addAttribute("Recipient", _destinationIRI);
		
		Element assertionConditions = assertion.addElement(new QName("Conditions", SAML_NS));
		assertionConditions.addAttribute("NotBefore", currentDate);
		assertionConditions.addAttribute("NotOnOrAfter", futureDate);
		
		Element assertionAudienceRestriction = assertionConditions.addElement(new QName("AudienceRestriction", SAML_NS));
		
		Element assertionAudience = assertionAudienceRestriction.addElement(new QName("Audience", SAML_NS));
		assertionAudience.setText(_audience);
		
		Element assertionAuthnStatement = assertion.addElement(new QName("AuthnStatement", SAML_NS));
		assertionAuthnStatement.addAttribute("AuthnInstant", currentDate);
		assertionAuthnStatement.addAttribute("SessionIndex", UUID.randomUUID().toString());
		
		Element assertionAuthnContext = assertionAuthnStatement.addElement(new QName("AuthnContext", SAML_NS));
		
		Element assertionAuthnContextClassRef = assertionAuthnContext.addElement(new QName("AuthnContextClassRef", SAML_NS));
		assertionAuthnContextClassRef.setText(constHandler.getAuthnContextClasses(_classes));
		
		this.signMessage(assertionID, _xmlsec);
	}
	
	/**
	 * @param _nodeID The identifier of the node that should be signed.
	 */
	private void signMessage(String _nodeID, XMLSecurity _xmlSec) {
		try {
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			_xmlSec.signDocument(os, this.xmlDocument.asXML(), _nodeID);
			SAXReader reader = new SAXReader();
			this.xmlDocument = reader.read(new ByteArrayInputStream(os.toString().getBytes()));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public String getStatus() { return this.getAttributeValue("/samlp:Response/samlp:Status/samlp:StatusCode", "Value"); }
	
	public String getIssuer() { return this.getElementValue("/samlp:Response/saml:Issuer"); }
	
	public String getSessionID() { return this.getAttributeValue("/samlp:Response/saml:Assertion/saml:AuthnStatement", "SessionIndex"); }
	
	public String getResponseID() { return this.getAttributeValue("/samlp:Response", "ID"); }
	public String getRequestID() { return this.getAttributeValue("/samlp:Response", "InResponseTo"); }
	public String getIssueInstant() { return this.getAttributeValue("/samlp:Response", "IssueInstant"); }
	public String getDestination() { return this.getAttributeValue("/samlp:Response", "Destination"); }
	
	public String getAssertionID() { return this.getAttributeValue("/samlp:Response/saml:Assertion", "ID"); }
	
	public String getNameID() { return this.getElementValue("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID"); }
	public String getNameIDFormat() { return this.getAttributeValue("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", "Format"); }
	
	public String getAuthnContextClassRef() { return this.getElementValue("/samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef"); }
	
	public String getAudience() { return this.getElementValue("/samlp:Response/saml:Assertion/saml:Conditions/saml:AudienceRestriction/saml:Audience"); }
	
	public String getNotOnOrAfter() { return this.getAttributeValue("/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", "NotOnOrAfter"); }

}
