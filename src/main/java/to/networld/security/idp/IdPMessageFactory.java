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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import to.networld.security.common.data.AuthnResponse;

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
	 * @throws IOException 
	 */
	public String createResponse(String _requestID, String _destinationIRI, String _audienceIRI, String _issuerIRI) throws IOException {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		AuthnResponse authnResponse = new AuthnResponse(_issuerIRI, _requestID, _destinationIRI, _audienceIRI);
		authnResponse.toXML(os);
		return os.toString();
	}
}
