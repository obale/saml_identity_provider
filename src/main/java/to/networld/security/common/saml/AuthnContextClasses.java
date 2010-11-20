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

import java.util.Vector;

/**
 * @author Alex Oberhauser
 */
public class AuthnContextClasses {
	
	public enum CLASSES {
		INTERNET_PROTOCOL,
		INTERNET_PROTOCOL_PASSWORD,
		KERBEROS,
		MOBILE_ONE_FACTOR_UNREGISTERED,
		MOBILE_TWO_FACTOR_UNREGISTERED,
		MOBILE_ONE_FACTOR_CONTRACT,
		MOBILE_TWO_FACTOR_CONTRACT,
		PASSWORD,
		PASSWORD_PROTECTED_TRANSPORT,
		PREVIOUS_SESSION,
		X509,
		PGP,
		SPKI,
		XML_DSIG,
		SMARTCARD,
		SMARTCARD_PKI,
		SOFTWARE_PKI,
		TELEPHONY,
		NOMADIC_TELEPHONY,
		PERSONAL_TELEPHONY,
		AUTHENTICATED_TELEPHONY,
		SECURE_REMOTE_PASSWORD,
		TLS_CLIENT,
		TIME_SYNC_TOKEN,
		UNSPECIFIED
	}
	
	private Vector<String> acClassesVector = new Vector<String>();
	
	private void initAcClassesVector() {
		String prefix = "urn:oasis:names:tc:SAML:2.0:ac:classes:";
		this.acClassesVector.add(prefix + "InternetProtocol");
		this.acClassesVector.add(prefix + "InternetProtocolPassword");
		this.acClassesVector.add(prefix + "Kerberos");
		this.acClassesVector.add(prefix + "MobileOneFactorUnregistered");
		this.acClassesVector.add(prefix + "MobileTwoFactorUnregistered");
		this.acClassesVector.add(prefix + "MobileOneFactorContract");
		this.acClassesVector.add(prefix + "MobileTwoFactorContract");
		this.acClassesVector.add(prefix + "Password");
		this.acClassesVector.add(prefix + "PasswordProtectedTransport");
		this.acClassesVector.add(prefix + "PreviousSession");
		this.acClassesVector.add(prefix + "X509");
		this.acClassesVector.add(prefix + "PGP");
		this.acClassesVector.add(prefix + "SPKI");
		this.acClassesVector.add(prefix + "XMLDSig");
		this.acClassesVector.add(prefix + "Smartcard");
		this.acClassesVector.add(prefix + "SmartcardPKI");
		this.acClassesVector.add(prefix + "SoftwarePKI");
		this.acClassesVector.add(prefix + "Telephony");
		this.acClassesVector.add(prefix + "NomadTelephony");
		this.acClassesVector.add(prefix + "PersonalTelephony");
		this.acClassesVector.add(prefix + "AuthenticatedTelephony");
		this.acClassesVector.add(prefix + "SecureRemotePassword");
		this.acClassesVector.add(prefix + "TLSClient");
		this.acClassesVector.add(prefix + "TimeSyncToken");
		this.acClassesVector.add(prefix + "Unspecified");
	}
	
	protected String getNameIDFormat(CLASSES _classes) {
		this.initAcClassesVector();
		return this.acClassesVector.get(_classes.ordinal());
	}
}
