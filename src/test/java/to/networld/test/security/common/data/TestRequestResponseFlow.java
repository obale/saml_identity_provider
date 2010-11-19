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

import java.io.IOException;

import org.junit.Assert;
import org.junit.Test;

import to.networld.security.common.data.AuthnRequest;
import to.networld.security.common.data.AuthnResponse;
import to.networld.security.idp.IdPMessageFactory;
import to.networld.security.sp.SPMessageFactory;

/**
 * @author Alex Oberhauser
 */
public class TestRequestResponseFlow {
	
	@Test
	public void testRequestResponseReferences() throws IOException {
		/*
		 * Create first a request message... 
		 */
		String spIssuerIRI = "http://sp.networld.to";
		
		SPMessageFactory spMsgFactory = SPMessageFactory.getInstance();
		AuthnRequest auth = spMsgFactory.createAuthnRequest(spIssuerIRI);
		
		Assert.assertEquals(auth.getIssuer(), spIssuerIRI);
		
		/*
		 * And now extract the needed information from the request message...
		 */
//		String gainedIssuer = auth.getIssuer();
//		String gainedIssuerInstant = auth.getIssueInstant();
		String gainedRequestID = auth.getRequestID();
		
		/*
		 * Create the response message... 
		 */
		String username = "John Doe";
		String destinationIRI = "http://sp.networld.to/SAML2/SSO/POST";
		String audienceIRI = "http://sp.networld.to/SAML2";
		String idpIssuerIRI ="https://idp.networld.to/SAML2"; 
		
		IdPMessageFactory idpMsgFactory = IdPMessageFactory.getInstance();
		AuthnResponse response = idpMsgFactory.createResponse(username,
				gainedRequestID, 
				destinationIRI,
				audienceIRI,
				idpIssuerIRI);
		
		Assert.assertEquals(response.getIssuer(), idpIssuerIRI);
		Assert.assertEquals(response.getDestination(), destinationIRI);
		Assert.assertEquals(response.getAudience(), audienceIRI);
		Assert.assertEquals(response.getNameID(), username);
		
		/*
		 * Check the cross references between the two messages...
		 */
		Assert.assertEquals(response.getRequestID(), auth.getRequestID());
	}
}
