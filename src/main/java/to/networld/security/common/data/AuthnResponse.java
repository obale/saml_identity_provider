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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.UUID;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Node;
import org.dom4j.io.SAXReader;
import org.xml.sax.SAXException;

import to.networld.security.common.DateHelper;
import to.networld.security.common.Keytool;
import to.networld.security.common.XMLSecurity;

/**
 * @author Alex Oberhauser
 */
public class AuthnResponse {
	private String issuer = null;
	private String responseID = null;
	private String assertionID = null;
	private String username = null;
	private String requestID = null;
	private String destinationIRI = null;
	private String audienceIRI = null;
	private String currentDate = null;
	private String futureDate = null;
	
	public AuthnResponse() {}
	
	public AuthnResponse(String _username, String _issuer, String _requestID, String _destinationIRI, String _audienceIRI) {
		this.issuer = _issuer;
		this.requestID = _requestID;
		this.destinationIRI = _destinationIRI;
		this.audienceIRI = _audienceIRI;
		this.responseID = UUID.randomUUID().toString();
		this.assertionID = UUID.randomUUID().toString();
		this.username = _username;
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
			this.username = nameIDNode.getText().trim();
		
		Node subjectConfirmationData = doc.selectSingleNode("/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData");
		if ( subjectConfirmationData != null )
			this.futureDate = subjectConfirmationData.valueOf("@NotOnOrAfter");
		
		Node audienceRestriction = doc.selectSingleNode("/samlp:Response/saml:Assertion/saml:Conditions/saml:AudienceRestriction/saml:Audience");
		if ( audienceRestriction != null )
			this.audienceIRI = audienceRestriction.getText().trim();
	}
	
	public String getIssuer() { return this.issuer; }
	public String getResponseID() { return this.responseID; }
	public String getAssertionID() { return this.assertionID; }
	
	public void toXML(OutputStream _os) throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableEntryException, InvalidAlgorithmParameterException, SAXException, ParserConfigurationException, MarshalException, XMLSignatureException, TransformerException {
		ByteArrayOutputStream tmpOS = new ByteArrayOutputStream();
		tmpOS.write("<samlp:Response\n".getBytes());
		tmpOS.write("\txmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n".getBytes());
		tmpOS.write("\txmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n".getBytes());
		tmpOS.write(("\tID=\"" + this.responseID + "\"\n").getBytes());
		tmpOS.write(("\tInResponseTo=\"" + this.requestID + "\"\n").getBytes());
		tmpOS.write("\tVersion=\"2.0\"\n".getBytes());
		tmpOS.write(("\tIssueInstant=\"" + this.currentDate + "\"\n").getBytes());
		tmpOS.write(("\tDestination=\"" + this.destinationIRI + "\">\n").getBytes());
		tmpOS.write(("\t<saml:Issuer>" + this.issuer + "</saml:Issuer>\n").getBytes());
		tmpOS.write("\t<samlp:Status>\n".getBytes());
		tmpOS.write("\t\t<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n".getBytes());
		tmpOS.write("\t</samlp:Status>\n".getBytes());
		tmpOS.write("\t<saml:Assertion\n".getBytes());
		tmpOS.write("\t\txmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n".getBytes());
		tmpOS.write(("\t\tID=\"" + this.assertionID  + "\"\n").getBytes());
		tmpOS.write("\t\tVersion=\"2.0\"\n".getBytes());
		tmpOS.write(("\t\tIssueInstant=\"" + currentDate + "\">\n").getBytes());
		tmpOS.write(("\t\t<saml:Issuer>" + issuer + "</saml:Issuer>\n").getBytes());
		tmpOS.write("\t\t<saml:Subject>\n".getBytes());
		tmpOS.write("\t\t\t<saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">\n".getBytes());
		tmpOS.write(("\t\t\t\t" + this.username + "\n").getBytes());
		tmpOS.write("\t\t\t</saml:NameID>\n".getBytes());
		tmpOS.write("\t\t\t<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n".getBytes());
		tmpOS.write("\t\t\t\t<saml:SubjectConfirmationData\n".getBytes());
		tmpOS.write(("\t\t\t\t\tInResponseTo=\"" + this.requestID + "\"\n").getBytes());
		tmpOS.write(("\t\t\t\t\tRecipient=\"" + this.destinationIRI + "\"\n").getBytes());
		tmpOS.write(("\t\t\t\t\tNotOnOrAfter=\"" + this.futureDate + "\"/>\n").getBytes());
		tmpOS.write("\t\t\t\t</saml:SubjectConfirmation>\n".getBytes());
		tmpOS.write("\t\t</saml:Subject>\n".getBytes());
		tmpOS.write("\t\t<saml:Conditions\n".getBytes());
		tmpOS.write(("\t\t\tNotBefore=\"" + this.currentDate + "\"\n").getBytes());
		tmpOS.write(("\t\t\tNotOnOrAfter=\"" + this.futureDate + "\">\n").getBytes());
		tmpOS.write("\t\t\t<saml:AudienceRestriction>\n".getBytes());
		tmpOS.write(("\t\t\t\t<saml:Audience>" + this.audienceIRI + "</saml:Audience>\n").getBytes());
		tmpOS.write("\t\t\t</saml:AudienceRestriction>\n".getBytes());
		tmpOS.write("\t\t</saml:Conditions>\n".getBytes());
		tmpOS.write("\t\t<saml:AuthnStatement\n".getBytes());
		tmpOS.write(("\t\t\tAuthnInstant=\"" + this.currentDate + "\"\n").getBytes());
		tmpOS.write(("\t\t\tSessionIndex=\"" + this.assertionID + "\">\n").getBytes());
		tmpOS.write("\t\t\t<saml:AuthnContext>\n".getBytes());
		tmpOS.write("\t\t\t\t<saml:AuthnContextClassRef>\n".getBytes());
		tmpOS.write("\t\t\t\t\turn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport\n".getBytes());
		tmpOS.write("\t\t\t\t</saml:AuthnContextClassRef>\n".getBytes());
		tmpOS.write("\t\t\t</saml:AuthnContext>\n".getBytes());
		tmpOS.write("\t\t</saml:AuthnStatement>\n".getBytes());
		tmpOS.write("\t</saml:Assertion>\n".getBytes());
		tmpOS.write("</samlp:Response>".getBytes());
		XMLSecurity xmlSec = new XMLSecurity(Keytool.class.getResourceAsStream("/keystore.jks"), "v3ryS3cr3t", "idproot", "v3ryS3cr3t");
		xmlSec.signDocument(_os, tmpOS.toString(), this.assertionID);
	}
	
	@Override
	public String toString() {
		try {
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			this.toXML(os);
			return os.toString();
		} catch (Exception e) {
			return null;
		}
	}
}
