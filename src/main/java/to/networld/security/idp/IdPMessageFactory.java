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

import java.io.IOException;

import to.networld.security.common.Base64Helper;
import to.networld.security.common.data.AuthnRequest;
import to.networld.security.common.data.AuthnResponse;
import to.networld.security.common.saml.AuthnContextClasses.AUTH_METHOD;
import to.networld.security.common.saml.NameIDFormat.ID_FORMAT;

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
	
	public String createXFormSAMLPart(String _username, String _requestID, String _destinationIRI, String _audienceIRI, String _issuerIRI, ID_FORMAT _format, AUTH_METHOD _classes) throws IOException {
		StringBuffer formPart = new StringBuffer();
		formPart.append("<input type=\"hidden\" name=\"SAMLResponse\" value=\"");
		formPart.append(Base64Helper.convertToBase64(this.createResponse(_username, _requestID, _destinationIRI, _audienceIRI, _issuerIRI, _format, _classes).toString().getBytes()));
		formPart.append("\" />\n");
		return formPart.toString();
	}
	
	public String createXFormSAMLPart(AuthnRequest _request, String _username, String _issuerIRI, ID_FORMAT _format, AUTH_METHOD _classes) throws IOException {
		String issuer = _request.getIssuer();
		return this.createXFormSAMLPart(_username, _request.getRequestID(), issuer, issuer, _issuerIRI, _format, _classes);
	}
	
	/**
	 * Create a response message if the authentication was a success.
	 * 
	 * @param _username
	 * @param _requestID
	 * @param _destinationIRI
	 * @param _issuerIRI
	 * @param _format The format of the _username (see {@link ID_FORMAT})
	 * @param _classes The authentication mechanism (see {@link AUTH_METHOD}) 
	 * @return The SAML response message for the singel sign-on process.
	 * @throws IOException 
	 */
	public AuthnResponse createResponse(String _username, String _requestID, String _destinationIRI, String _audienceIRI, String _issuerIRI, ID_FORMAT _format, AUTH_METHOD _classes) throws IOException {
		return new AuthnResponse(_username, _issuerIRI, _requestID, _destinationIRI, _audienceIRI, _format, _classes);
	}
	
	public AuthnResponse createResponse(AuthnRequest _request, String _username, String _issuerIRI, ID_FORMAT _format, AUTH_METHOD _classes) throws IOException {
		String issuer = _request.getIssuer();
		return this.createResponse(_username, _request.getRequestID(), issuer, issuer, _issuerIRI, _format, _classes);
	}
}
