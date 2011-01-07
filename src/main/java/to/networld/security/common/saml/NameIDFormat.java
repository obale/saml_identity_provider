/**
 * identity_provider - to.networld.security.common.saml
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

package to.networld.security.common.saml;

import java.util.Vector;

/**
 * @author Alex Oberhauser
 */
public class NameIDFormat {
	
	public enum ID_FORMAT {
		UNSPECIFIED,
		EMAIL,
		X509_SUBJECT_NAME,
		WINDOWS_DOMAIN_QUALIFIED_NAME,
		KERBEROS,
		ENTITY,
		PERSISTENT,
		TRANSIENT
	}
	
	private Vector<String> nameIDFormatVector = new Vector<String>();
	
	private void initNameIDFormatVector() {
		String prefix = "urn:oasis:names:tc:SAML:2.0:nameid-format:";
		this.nameIDFormatVector.add(prefix + "unspecified");
		this.nameIDFormatVector.add(prefix + "emailAddress");
		this.nameIDFormatVector.add(prefix + "X509SubjectName");
		this.nameIDFormatVector.add(prefix + "WindowsDomainQualifiedName");
		this.nameIDFormatVector.add(prefix + "kerberos");
		this.nameIDFormatVector.add(prefix + "entity");
		this.nameIDFormatVector.add(prefix + "persistent");
		this.nameIDFormatVector.add(prefix + "transient");
	}
	
	protected String getNameIDFormat(ID_FORMAT _format) {
		this.initNameIDFormatVector();
		return this.nameIDFormatVector.get(_format.ordinal());
	}
}
