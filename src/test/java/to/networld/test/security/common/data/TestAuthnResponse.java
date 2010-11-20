/**
 * identity_provider - to.networld.test.security.common.data
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

package to.networld.test.security.common.data;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

import org.dom4j.DocumentException;
import org.junit.Assert;
import org.junit.Test;
import org.xml.sax.SAXException;

import to.networld.security.common.data.AuthnResponse;
import to.networld.security.common.saml.AuthnContextClasses.CLASSES;
import to.networld.security.common.saml.NameIDFormat.FORMAT;

/**
 * @author Alex Oberhauser
 */
public class TestAuthnResponse {
	
	/**
	 * Tests the serialization of the SAML AuthnRequest message.
	 * @throws TransformerException 
	 * @throws XMLSignatureException 
	 * @throws MarshalException 
	 * @throws ParserConfigurationException 
	 * @throws SAXException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws UnrecoverableEntryException 
	 * @throws KeyStoreException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 */
	@Test
	public void testToFromXML() throws NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableEntryException, InvalidAlgorithmParameterException, SAXException, ParserConfigurationException, MarshalException, XMLSignatureException, TransformerException {
		try {
			AuthnResponse orgAuthnResponse = new AuthnResponse("john.doe@example.org",
					"http://idp.networld.to/SAML2", 
					UUID.randomUUID().toString(), 
					"http://sp.networld.to/SAML2/SSO/POST", 
					"http://sp.networld.to/SAML2",
					FORMAT.EMAIL, CLASSES.PASSWORD_PROTECTED_TRANSPORT);
			ByteArrayOutputStream orgOut = new ByteArrayOutputStream();
			orgAuthnResponse.toXML(orgOut);
			
			AuthnResponse loadedAuthnResponse = new AuthnResponse();
			ByteArrayOutputStream loadedOut = new ByteArrayOutputStream();
			loadedAuthnResponse.load(new ByteArrayInputStream(orgOut.toByteArray()));
			loadedAuthnResponse.toXML(loadedOut);
			Assert.assertEquals(orgOut.toString(), loadedOut.toString());
		} catch (IOException e) {
			Assert.assertTrue(false);
		} catch (DocumentException e) {
			Assert.assertTrue(false);
		}
	}
}
