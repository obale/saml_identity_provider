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
import java.util.UUID;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Node;
import org.dom4j.io.SAXReader;

import to.networld.security.common.DateHelper;

/**
 * @author Alex Oberhauser
 */
public class AuthnRequest {	
	private String issuer = null;
	private String requestID = null;
	private String issueInstant = null;
	
	public AuthnRequest() {}
	
	public AuthnRequest(String _issuer) {
		this.issuer = _issuer;
		this.requestID = UUID.randomUUID().toString();
		this.issueInstant = DateHelper.getCurrentDate();
	}
	
	public AuthnRequest(String _issuer, String _requestID) {
		this.issuer = _issuer;
		this.requestID = _requestID;
		this.issueInstant = DateHelper.getCurrentDate();
	}
	
	public void load(InputStream _is) throws DocumentException {
		SAXReader reader = new SAXReader();
		Document doc = reader.read(_is);
		
		Node issuerNode = doc.selectSingleNode("/samlp:AuthnRequest/saml:Issuer");
		if ( issuerNode != null )
			this.issuer = issuerNode.getText().trim();
		
		Node requestNode = doc.selectSingleNode("/samlp:AuthnRequest");
		if ( requestNode != null ) {
			this.requestID = requestNode.valueOf("@ID");
			this.issueInstant = requestNode.valueOf("@IssueInstant");
		}
	}
	
	public String getIssuer() { return this.issuer; }
	public String getIssuerInstant() { return this.issueInstant; }
	public String getRequestID() { return this.requestID; }
	
	public void toXML(OutputStream _os) throws IOException {
		_os.write("<samlp:AuthnRequest\n".getBytes());
		_os.write("\txmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n".getBytes());
		_os.write("\txmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n".getBytes());
		_os.write(("\tID=\"" + this.requestID + "\"\n").getBytes());
		_os.write("\tVersion=\"2.0\"\n".getBytes());
		_os.write(("\tIssueInstant=\"" + this.issueInstant + "\"\n").getBytes());
		_os.write("\tAssertionConsumerServiceIndex=\"0\"\n".getBytes());
		_os.write("\tAttributeConsumingServiceIndex=\"0\">\n".getBytes());
		_os.write(("\t<saml:Issuer>" + this.issuer + "</saml:Issuer>\n").getBytes());
		_os.write("\t<samlp:NameIDPolicy AllowCreate=\"true\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\"/>\n".getBytes());
		_os.write("</samlp:AuthnRequest>".getBytes());
		_os.flush();
		_os.close();
	}
	
	@Override
	public String toString() {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		try {
			this.toXML(os);
			return os.toString();
		} catch (IOException e) {
			return null;
		}
	}
}
