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

package to.networld.security.sp;

import java.io.IOException;

import to.networld.security.common.Base64Helper;
import to.networld.security.common.data.AuthnRequest;

/**
 * @author Alex Oberhauser
 */
public class SPMessageFactory {
	private static SPMessageFactory instance = null;
	
	private SPMessageFactory() {}
	
	public static SPMessageFactory getInstance() {
		if ( instance == null ) {
			instance = new SPMessageFactory();
		}
		return instance;
	}
	
	public String createXFormSAMLPart(String _issuerIRI) throws IOException {
		StringBuffer formPart = new StringBuffer();
		formPart.append("<input type=\"hidden\" name=\"SAMLRequest\" value=\"");
		formPart.append(Base64Helper.convertToBase64(this.createAuthnRequest(_issuerIRI).toString().getBytes()));
		formPart.append("\" />\n");
		return formPart.toString();
	}
	
	/**
	 * Creates the SAML authentication message.
	 * 
	 * @param _issuerIRI
	 * @return The SAML authentication request message.
	 * @throws IOException 
	 */
	public AuthnRequest createAuthnRequest(String _issuerIRI) throws IOException {
		return new AuthnRequest(_issuerIRI);
	}
}
