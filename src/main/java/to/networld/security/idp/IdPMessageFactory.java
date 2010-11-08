/**
 * identity_provider - to.networld.security.idp
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

package to.networld.security.idp;

import java.util.UUID;

import to.networld.security.common.DateHelper;

/**
 * @author Alex Oberhauser
 */
public class IdPMessageFactory {
	private static IdPMessageFactory instance = null;
	
	private IdPMessageFactory() {}
	
	public static IdPMessageFactory getInstance() {
		if ( instance == null ) {
			instance = new IdPMessageFactory();
		}
		return instance;
	}
	
	/**
	 * Create a response message if the authentication was a success.
	 * 
	 * @param _requestID
	 * @param _destinationIRI
	 * @param _issuerIRI
	 * @return The SAML response message for the singel sign-on process.
	 */
	public String createResponse(String _requestID, String _destinationIRI, String _audienceIRI, String _issuerIRI) {
		StringBuffer response = new StringBuffer();
		
		String currentDate = DateHelper.getCurrentDate();
		
		response.append("<samlp:Response\n");
		response.append("\txmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n");
		response.append("\txmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n");
		response.append("\tID=\"" + UUID.randomUUID().toString() + "\"\n");
		response.append("\tInResponseTo=\"" + _requestID + "\"\n");
		response.append("\tVersion=\"2.0\"\n");
		response.append("\tIssueInstant=\"" + DateHelper.getCurrentDate() + "\"\n");
		response.append("\tDestination=\"" + _destinationIRI + "\">\n");
		response.append("\t<saml:Issuer>" + _issuerIRI + "</saml:Issuer>\n");
		response.append("\t<samlp:Status>\n");
		response.append("\t\t<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n");
		response.append("\t</samlp:Status>\n");
		response.append("\t<saml:Assertion\n");
		response.append("\t\txmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n");
		String assertionID = UUID.randomUUID().toString();
		response.append("\t\tID=\"" + assertionID  + "\"\n");
		response.append("\t\tVersion=\"2.0\"\n");
		response.append("\t\tIssueInstant=\"" + currentDate + "\"\n");
		response.append("\t\t<saml:Issuer>" + _issuerIRI + "</saml:Issuer>\n");
		response.append("\t\t<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n");
		response.append("\t\t\t<!-- Here comes the signature -->\n");
		response.append("\t\t</ds:Signature>\n");
		response.append("\t\t<saml:Subject>\n");
		response.append("\t\t\t<saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">\n");
		response.append("\t\t\t\t" + UUID.randomUUID() + "\n");
		response.append("\t\t\t</saml:NameID>\n");
		response.append("\t\t\t<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n");
		response.append("\t\t\t\t<saml:SubjectConfirmationData\n");
		response.append("\t\t\t\t\tInResponseTo=\"" + _requestID + "\"\n");
		response.append("\t\t\t\t\tRecipient=\"" + _destinationIRI + "\"\n");
		String futureDate = DateHelper.getFutureDate(10);
		response.append("\t\t\t\t\tNotOnOrAfter=\"" + futureDate + "\"/>\n");
		response.append("\t\t\t\t</saml:SubjectConfirmation>\n");
		response.append("\t\t</saml:Subject>\n");
		response.append("\t\t<saml:Conditions\n");
		response.append("\t\t\tNotBefore=\"" + currentDate + "\"\n");
		response.append("\t\t\tNotOnOrAfter=\"" + futureDate + "\">\n");
		response.append("\t\t\t<saml:AudienceRestriction>\n");
		response.append("\t\t\t\t<saml:Audience>" + _audienceIRI + "</saml:Audience>\n");
		response.append("\t\t\t</saml:AudienceRestriction>\n");
		response.append("\t\t</saml:Conditions>\n");
		response.append("\t\t<saml:AuthnStatement\n");
		response.append("\t\t\tAuthnInstant=\"" + currentDate + "\"\n");
		response.append("\t\t\tSessionIndex=\"" + assertionID + "\">\n");
		response.append("\t\t\t<saml:AuthnContext>\n");
		response.append("\t\t\t\t<saml:AuthnContextClassRef>\n");
		response.append("\t\t\t\t\turn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport\n");
		response.append("\t\t\t\t</saml:AuthnContextClassRef>\n");
		response.append("\t\t\t</saml:AuthnContext>\n");
		response.append("\t\t</saml:AuthnStatement\n");
		response.append("\t</saml:Assertion\n");
		response.append("</samlp:Response>");
		
		return response.toString();
	}
}
