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

import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentFactory;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;

/**
 * Abstract class that should be extended if the class 
 * 
 * @author Alex Oberhauser
 */
public abstract class GenericSAMLMessage {
	private DocumentFactory factory = DocumentFactory.getInstance();
	
	protected Document xmlDocument = this.factory.createDocument();
	
	protected Namespace SAML_NS = this.factory.createNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
	protected Namespace SAMLP_NS = this.factory.createNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
	
	/**
	 * Extracts the parameter from XML message that is stored in the InputStream
	 *  _is and stores them in the current object.
	 * 
	 * ATTENTION: Please assure that you chose the right object for the input
	 *            message to be able to extract the values.
	 *  
	 * @param _is The InputStream that includes the XML message to load.
	 * @throws DocumentException
	 */
	public void load(InputStream _is) throws DocumentException {
		SAXReader reader = new SAXReader();
		this.xmlDocument = reader.read(_is);
	}
	
	/**
	 * Extracts a SAML2.0 message from a SOAP message.
	 * 
	 * @param _soapMessage The SOAP message that includes the SAML2.0 message in the body.
	 */
	public abstract void load(SOAPMessage _soapMessage) throws SOAPException;
	
	protected String getAttributeValue(String _xpath, String _attribute) {
		Element element = (Element)this.xmlDocument.selectSingleNode(_xpath);
		if ( element != null )
			return element.attributeValue(_attribute);
		else
			return null;
	}
	
	protected String getElementValue(String _xpath) {
		Element element = (Element)this.xmlDocument.selectSingleNode(_xpath);
		if ( element != null )
			return element.getTextTrim();
		else
			return null;
	}
	
	/**
	 * Serializes the current object to a XML message and stores the gained
	 * XML message to the OutputStream _os.
	 * 
	 * @param _os The OutputStream that should whole the newly create XML message.
	 * @throws IOException
	 */
	public void toXML(OutputStream _os) throws IOException {
		_os.write(this.xmlDocument.asXML().getBytes());
	}
	
	/**
	 * Force the subclass to override the toString() method.
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		try {
			OutputFormat format = OutputFormat.createPrettyPrint();
			XMLWriter writer = new XMLWriter(os, format);
			writer.write(this.xmlDocument);
			return os.toString();
		} catch (IOException e) {
			return null;
		}
	}
	
}
