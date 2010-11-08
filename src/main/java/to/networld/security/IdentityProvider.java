/**
 * identity_provider - to.networld.security
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

package to.networld.security;

import java.util.UUID;

import org.apache.log4j.Logger;

import to.networld.security.common.Base64Helper;
import to.networld.security.idp.IdPMessageFactory;
import to.networld.security.sp.SPMessageFactory;

/**
 * @author Alex Oberhauser
 */
public class IdentityProvider  {
	
	private static String issuerIRI = "http://sp.networld.to/SAML2";
	private static String authID = UUID.randomUUID().toString();
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Logger log = Logger.getLogger(IdentityProvider.class);
		
		SPMessageFactory spMsgFactory = SPMessageFactory.getInstance();
		String auth = spMsgFactory.createAuthnRequest(issuerIRI, authID);
		log.trace("\n--- BEGIN AuthnRequest ---\n" + auth + "\n--- END AuthnRequest ---\n");
		log.trace("\n--- BEGIN X-Form Part ---\n" + spMsgFactory.createXFormSAMLPart(issuerIRI, authID) + "\n--- END X-Form Part---\n");
		
		IdPMessageFactory idpMsgFactory = IdPMessageFactory.getInstance();
		String response = idpMsgFactory.createResponse(authID, 
				"http://sp.networld.to/SAML2/SSO/POST",
				"http://sp.networld.to/SAML2",
				"https://idp.networld.to/SAML2");
		log.trace("\n--- BEGIN Response ---\n" + response + "\n--- END Response ---\n");
		log.trace("\n--- BEGIN Response (Base64) ---\n" + Base64Helper.convertToBase64(response.getBytes()) + "\n--- END Response (Base64) ---\n");

	}

}
