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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.UUID;

import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

import org.dom4j.Element;
import org.dom4j.QName;
import org.dom4j.io.SAXReader;

import to.networld.security.common.DateHelper;
import to.networld.security.common.XMLSecurity;

/**
 * @author Alex Oberhauser
 */
public class ArtifactResolve extends GenericSAMLMessage {
	
	public ArtifactResolve() {}
	
	public ArtifactResolve(XMLSecurity _xmlSec, String _issuer, String _destination, String _artifactID) {
		String id = UUID.randomUUID().toString();
		this.writeMessage(id, _issuer, _artifactID, _destination, "2.0", DateHelper.getCurrentDate());
		this.signMessage(id, _xmlSec);
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
	
	private void writeMessage(String _id, String _issuer, String _artifactID, String _destination, String _version, String _issueInstant) {
		Element artifactResolveNode = this.xmlDocument.addElement(new QName("ArtifactResolve", SAMLP_NS));
		artifactResolveNode.add(SAML_NS);
		
		artifactResolveNode.addAttribute("ID", _id);
		artifactResolveNode.addAttribute("Version", _version);
		artifactResolveNode.addAttribute("IssueInstant", _issueInstant);
		artifactResolveNode.addAttribute("Destination", _destination);
		
		Element issuerNode = artifactResolveNode.addElement(new QName("Issuer", SAML_NS));
		issuerNode.addText(_issuer);
		
		Element artifactNode = artifactResolveNode.addElement(new QName("Artifact", SAMLP_NS));
		artifactNode.setText(_artifactID);
	}

	/**
	 * @see to.networld.security.common.data.GenericSAMLMessage#load(javax.xml.soap.SOAPMessage)
	 */
	@Override
	public void load(SOAPMessage soapMessage) throws SOAPException {
		// TODO Auto-generated method stub
	}

}
