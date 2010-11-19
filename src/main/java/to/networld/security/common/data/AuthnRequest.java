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

import java.util.UUID;

import org.dom4j.Element;
import org.dom4j.QName;

import to.networld.security.common.DateHelper;

/**
 * @author Alex Oberhauser
 */
public class AuthnRequest extends MarshallingObject {	
	
	public AuthnRequest() {}
	
	public AuthnRequest(String _issuer) {
		Element authnRequestNode = this.xmlDocument.addElement(new QName("AuthnRequest", SAMLP_NS));
		authnRequestNode.add(SAML_NS);
		
		authnRequestNode.addAttribute("ID", UUID.randomUUID().toString());
		authnRequestNode.addAttribute("Version", "2.0");
		authnRequestNode.addAttribute("IssueInstant", DateHelper.getCurrentDate());
		authnRequestNode.addAttribute("AssertionConsumerServiceIndex", "0");
		authnRequestNode.addAttribute("AttributeConsumingServiceIndex", "0");
		
		Element issuerNode = authnRequestNode.addElement(new QName("Issuer", SAML_NS));
		issuerNode.setText(_issuer);
		
		Element namedIDPolicyNode = authnRequestNode.addElement(new QName("NameIDPolicy", SAMLP_NS));
		namedIDPolicyNode.addAttribute("AllowCreate", "true");
		namedIDPolicyNode.addAttribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
	}
	
	public String getIssuer() { return this.getElementValue("/samlp:AuthnRequest/saml:Issuer"); }
	public String getIssueInstant() { return this.getAttributeValue("/samlp:AuthnRequest", "IssueInstant"); }
	public String getRequestID() { return this.getAttributeValue("/samlp:AuthnRequest", "ID"); }
	
}
