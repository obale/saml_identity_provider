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
import java.util.UUID;

import org.dom4j.DocumentException;
import org.junit.Assert;
import org.junit.Test;

import to.networld.security.common.data.AuthnRequest;

/**
 * @author Alex Oberhauser
 */
public class TestAuthnRequest {
	
	/**
	 * Tests the serialization of the SAML AuthnRequest message.
	 */
	@Test
	public void testToFromXML() {
		try {
			AuthnRequest orgAuthnRequest = new AuthnRequest("http://sp.networld.to/SAML2", UUID.randomUUID().toString());
			ByteArrayOutputStream orgOut = new ByteArrayOutputStream();
			orgAuthnRequest.toXML(orgOut);
			
			AuthnRequest loadedAuthnRequest = new AuthnRequest();
			ByteArrayOutputStream loadedOut = new ByteArrayOutputStream();
			loadedAuthnRequest.load(new ByteArrayInputStream(orgOut.toByteArray()));
			loadedAuthnRequest.toXML(loadedOut);
			
			Assert.assertEquals(orgOut.toString(), loadedOut.toString());
		} catch (IOException e) {
			Assert.assertTrue(false);
		} catch (DocumentException e) {
			Assert.assertTrue(false);
		}
	}
}
