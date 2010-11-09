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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.UUID;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Node;
import org.dom4j.io.SAXReader;

import to.networld.security.common.DateHelper;

/**
 * @author Alex Oberhauser
 */
public class AuthnResponse {
	private String issuer = null;
	private String responseID = null;
	private String assertionID = null;
	private String arifactID = null;
	private String requestID = null;
	private String destinationIRI = null;
	private String audienceIRI = null;
	private String currentDate = null;
	private String futureDate = null;
	
	public AuthnResponse() {}
	
	public AuthnResponse(String _issuer, String _requestID, String _destinationIRI, String _audienceIRI) {
		this.issuer = _issuer;
		this.requestID = _requestID;
		this.destinationIRI = _destinationIRI;
		this.audienceIRI = _audienceIRI;
		this.responseID = UUID.randomUUID().toString();
		this.assertionID = UUID.randomUUID().toString();
		this.arifactID = UUID.randomUUID().toString();
		this.currentDate = DateHelper.getCurrentDate();
		this.futureDate = DateHelper.getFutureDate(10);
	}
	
	public void load(InputStream _is) throws DocumentException {
		SAXReader reader = new SAXReader();
		Document doc = reader.read(_is);
		
		Node issuerNode = doc.selectSingleNode("/samlp:Response/saml:Issuer");
		if ( issuerNode != null )
			this.issuer = issuerNode.getText();

		Node responseNode = doc.selectSingleNode("/samlp:Response");
		if ( responseNode != null ) {
			this.responseID = responseNode.valueOf("@ID");
			this.requestID = responseNode.valueOf("@InResponseTo");
			this.currentDate = responseNode.valueOf("@IssueInstant");
			this.destinationIRI = responseNode.valueOf("@Destination");
		}
		
		Node assertionNode = doc.selectSingleNode("/samlp:Response/saml:Assertion");
		if ( assertionNode != null )
			this.assertionID = assertionNode.valueOf("@ID");
		
		Node nameIDNode = doc.selectSingleNode("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID");
		if ( nameIDNode != null )
			this.arifactID = nameIDNode.getText().trim();
		
		Node subjectConfirmationData = doc.selectSingleNode("/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData");
		if ( subjectConfirmationData != null )
			this.futureDate = subjectConfirmationData.valueOf("@NotOnOrAfter");
		
		Node audienceRestriction = doc.selectSingleNode("/samlp:Response/saml:Assertion/saml:Conditions/saml:AudienceRestriction/saml:Audience");
		if ( audienceRestriction != null )
			this.audienceIRI = audienceRestriction.getText().trim();
	}
	
	public void toXML(OutputStream _os) throws IOException {

		_os.write("<samlp:Response\n".getBytes());
		_os.write("\txmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n".getBytes());
		_os.write("\txmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n".getBytes());
		_os.write(("\tID=\"" + this.responseID + "\"\n").getBytes());
		_os.write(("\tInResponseTo=\"" + this.requestID + "\"\n").getBytes());
		_os.write("\tVersion=\"2.0\"\n".getBytes());
		_os.write(("\tIssueInstant=\"" + this.currentDate + "\"\n").getBytes());
		_os.write(("\tDestination=\"" + this.destinationIRI + "\">\n").getBytes());
		_os.write(("\t<saml:Issuer>" + this.issuer + "</saml:Issuer>\n").getBytes());
		_os.write("\t<samlp:Status>\n".getBytes());
		_os.write("\t\t<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n".getBytes());
		_os.write("\t</samlp:Status>\n".getBytes());
		_os.write("\t<saml:Assertion\n".getBytes());
		_os.write("\t\txmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n".getBytes());
		_os.write(("\t\tID=\"" + this.assertionID  + "\"\n").getBytes());
		_os.write("\t\tVersion=\"2.0\"\n".getBytes());
		_os.write(("\t\tIssueInstant=\"" + currentDate + "\">\n").getBytes());
		_os.write(("\t\t<saml:Issuer>" + issuer + "</saml:Issuer>\n").getBytes());
		_os.write("\t\t<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n".getBytes());
		_os.write("\t\t\t<!-- Here comes the signature -->\n".getBytes());
		_os.write("\t\t</ds:Signature>\n".getBytes());
		_os.write("\t\t<saml:Subject>\n".getBytes());
		_os.write("\t\t\t<saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">\n".getBytes());
		_os.write(("\t\t\t\t" + this.arifactID + "\n").getBytes());
		_os.write("\t\t\t</saml:NameID>\n".getBytes());
		_os.write("\t\t\t<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n".getBytes());
		_os.write("\t\t\t\t<saml:SubjectConfirmationData\n".getBytes());
		_os.write(("\t\t\t\t\tInResponseTo=\"" + requestID + "\"\n").getBytes());
		_os.write(("\t\t\t\t\tRecipient=\"" + destinationIRI + "\"\n").getBytes());
		_os.write(("\t\t\t\t\tNotOnOrAfter=\"" + futureDate + "\"/>\n").getBytes());
		_os.write("\t\t\t\t</saml:SubjectConfirmation>\n".getBytes());
		_os.write("\t\t</saml:Subject>\n".getBytes());
		_os.write("\t\t<saml:Conditions\n".getBytes());
		_os.write(("\t\t\tNotBefore=\"" + this.currentDate + "\"\n").getBytes());
		_os.write(("\t\t\tNotOnOrAfter=\"" + futureDate + "\">\n").getBytes());
		_os.write("\t\t\t<saml:AudienceRestriction>\n".getBytes());
		_os.write(("\t\t\t\t<saml:Audience>" + audienceIRI + "</saml:Audience>\n").getBytes());
		_os.write("\t\t\t</saml:AudienceRestriction>\n".getBytes());
		_os.write("\t\t</saml:Conditions>\n".getBytes());
		_os.write("\t\t<saml:AuthnStatement\n".getBytes());
		_os.write(("\t\t\tAuthnInstant=\"" + this.currentDate + "\"\n").getBytes());
		_os.write(("\t\t\tSessionIndex=\"" + assertionID + "\">\n").getBytes());
		_os.write("\t\t\t<saml:AuthnContext>\n".getBytes());
		_os.write("\t\t\t\t<saml:AuthnContextClassRef>\n".getBytes());
		_os.write("\t\t\t\t\turn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport\n".getBytes());
		_os.write("\t\t\t\t</saml:AuthnContextClassRef>\n".getBytes());
		_os.write("\t\t\t</saml:AuthnContext>\n".getBytes());
		_os.write("\t\t</saml:AuthnStatement>\n".getBytes());
		_os.write("\t</saml:Assertion>\n".getBytes());
		_os.write("</samlp:Response>".getBytes());
	}
}
