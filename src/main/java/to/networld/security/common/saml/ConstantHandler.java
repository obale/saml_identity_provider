/**
 * identity_provider - to.networld.security.common.saml
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

package to.networld.security.common.saml;

import to.networld.security.common.saml.AuthnContextClasses.AUTH_METHOD;
import to.networld.security.common.saml.NameIDFormat.ID_FORMAT;

/**
 * @author Alex Oberhauser
 */
public class ConstantHandler {
	private static ConstantHandler instance = null;
	private final NameIDFormat nameIDformat;
	private final AuthnContextClasses authnContextClasses;
	
	private ConstantHandler() {
		this.nameIDformat = new NameIDFormat();
		this.authnContextClasses = new AuthnContextClasses();
	}
	
	public static ConstantHandler getInstance() {
		if ( instance == null )
			instance = new ConstantHandler();
		return instance;
	}
	
	/**
	 * Expands the enumeration value (integer) to the corresponding String.
	 * 
	 * @param _format One of the entries in {@link ID_FORMAT}
	 * @return The representation of the format in SAML2.0 string.
	 */
	public String getNameIDFormat(ID_FORMAT _format) {
		return this.nameIDformat.getNameIDFormat(_format);
	}
	
	/**
	 * Expands the enumeration value (integer) to the corresponding String.
	 * 
	 * @param _classes One of the entries in {@link AUTH_METHOD} 
	 * @return The representation of the authentication method in SAML2.0 string.
	 */
	public String getAuthnContextClasses(AUTH_METHOD _classes) {
		return this.authnContextClasses.getNameIDFormat(_classes);
	}
}
