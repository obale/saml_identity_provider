/**
 * identity_provider - to.networld.test.security.common.saml
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

package to.networld.test.security.common.saml;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

import to.networld.security.common.saml.ConstantHandler;
import to.networld.security.common.saml.AuthnContextClasses.AUTH_METHOD;
import to.networld.security.common.saml.NameIDFormat.ID_FORMAT;

/**
 * @author Alex Oberhauser
 */
public class TestConstantHandler {
	private static ConstantHandler constHandler = null;
	
	@Before
	public void init() {
		constHandler = ConstantHandler.getInstance();
	}
	
	@Test
	public void testNameIDFormat() {
		String nameIDprefix = "urn:oasis:names:tc:SAML:2.0:nameid-format:";
		
		String unspecified = nameIDprefix + "unspecified";
		Assert.assertEquals(constHandler.getNameIDFormat(ID_FORMAT.UNSPECIFIED), unspecified);
		
		String email = nameIDprefix + "emailAddress";
		Assert.assertEquals(constHandler.getNameIDFormat(ID_FORMAT.EMAIL), email);
		
		String x509 = nameIDprefix + "X509SubjectName";
		Assert.assertEquals(constHandler.getNameIDFormat(ID_FORMAT.X509_SUBJECT_NAME), x509);
		
		String windows = nameIDprefix + "WindowsDomainQualifiedName";
		Assert.assertEquals(constHandler.getNameIDFormat(ID_FORMAT.WINDOWS_DOMAIN_QUALIFIED_NAME), windows);
		
		String kerberos = nameIDprefix + "kerberos";
		Assert.assertEquals(constHandler.getNameIDFormat(ID_FORMAT.KERBEROS), kerberos);
		
		String entity = nameIDprefix + "entity";
		Assert.assertEquals(constHandler.getNameIDFormat(ID_FORMAT.ENTITY), entity);
		
		String persistent = nameIDprefix + "persistent";
		Assert.assertEquals(constHandler.getNameIDFormat(ID_FORMAT.PERSISTENT), persistent);
		
		String trans = nameIDprefix + "transient";
		Assert.assertEquals(constHandler.getNameIDFormat(ID_FORMAT.TRANSIENT), trans);
	}
	
	@Test
	public void testAuthnContextClasses() {
		String authnContextPrefix = "urn:oasis:names:tc:SAML:2.0:ac:classes:";
		
		String ip = authnContextPrefix + "InternetProtocol";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.INTERNET_PROTOCOL), ip);
		
		String ipPassword = authnContextPrefix + "InternetProtocolPassword";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.INTERNET_PROTOCOL_PASSWORD), ipPassword);
		
		String authnKerberos = authnContextPrefix + "Kerberos";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.KERBEROS), authnKerberos);
		
		String mobileOneUnre = authnContextPrefix + "MobileOneFactorUnregistered";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.MOBILE_ONE_FACTOR_UNREGISTERED), mobileOneUnre);
		
		String mobileTwoUnre = authnContextPrefix + "MobileTwoFactorUnregistered";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.MOBILE_TWO_FACTOR_UNREGISTERED), mobileTwoUnre);
		
		String mobileOneCon = authnContextPrefix + "MobileOneFactorContract";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.MOBILE_ONE_FACTOR_CONTRACT), mobileOneCon);
		
		String mobileTwoCon = authnContextPrefix + "MobileTwoFactorContract";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.MOBILE_TWO_FACTOR_CONTRACT), mobileTwoCon);
		
		String pwd = authnContextPrefix + "Password";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.PASSWORD), pwd);
		
		String pwdProtected = authnContextPrefix + "PasswordProtectedTransport";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.PASSWORD_PROTECTED_TRANSPORT), pwdProtected);
		
		String previous = authnContextPrefix + "PreviousSession";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.PREVIOUS_SESSION), previous);
		
		String ax509 = authnContextPrefix + "X509";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.X509), ax509);
		
		String pgp = authnContextPrefix + "PGP";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.PGP), pgp);
		
		String spki = authnContextPrefix + "SPKI";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.SPKI), spki);
		
		String xmlDSig = authnContextPrefix + "XMLDSig";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.XML_DSIG), xmlDSig);
		
		String smartcard = authnContextPrefix + "Smartcard";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.SMARTCARD), smartcard);
		
		String smartcardPKI = authnContextPrefix + "SmartcardPKI";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.SMARTCARD_PKI), smartcardPKI);
		
		String softwarePKI = authnContextPrefix + "SoftwarePKI";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.SOFTWARE_PKI), softwarePKI);
		
		String tele = authnContextPrefix + "Telephony";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.TELEPHONY), tele);
		
		String nomTele = authnContextPrefix + "NomadTelephony";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.NOMADIC_TELEPHONY), nomTele);
		
		String persTele = authnContextPrefix + "PersonalTelephony";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.PERSONAL_TELEPHONY), persTele);
		
		String authTele = authnContextPrefix + "AuthenticatedTelephony";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.AUTHENTICATED_TELEPHONY), authTele);
		
		String tls = authnContextPrefix + "TLSClient";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.TLS_CLIENT), tls);
		
		String tst = authnContextPrefix + "TimeSyncToken";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.TIME_SYNC_TOKEN), tst);
		
		String unspecified = authnContextPrefix + "Unspecified";
		Assert.assertEquals(constHandler.getAuthnContextClasses(AUTH_METHOD.UNSPECIFIED), unspecified);
	}
}
