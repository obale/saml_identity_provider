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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;


import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;


import org.junit.Assert;
import org.junit.Test;
import org.xml.sax.SAXException;

import to.networld.security.common.data.AuthnResponseError;
import to.networld.security.common.data.AuthnResponseError.CODE;


/**
 * @author Alex Oberhauser
 */
public class TestAuthnResponseError {
	
	/**
	 * Tests the serialization of the SAML AuthnRequest message.
	 * @throws TransformerException 
	 * @throws XMLSignatureException 
	 * @throws MarshalException 
	 * @throws ParserConfigurationException 
	 * @throws SAXException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws UnrecoverableEntryException 
	 * @throws KeyStoreException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 */
	@Test
	public void testToFromXML() throws NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableEntryException, InvalidAlgorithmParameterException, SAXException, ParserConfigurationException, MarshalException, XMLSignatureException, TransformerException {
		String prefix = "urn:oasis:names:tc:SAML:2.0:status:";
		
		String requester = prefix + "Requester";
		String responder = prefix + "Responder";
		String versionMismatch = prefix + "VersionMismatch";
		String authnFailed = prefix + "AuthnFailed";
		String invalidAttr = prefix + "InvalidAttrNameOrValue";
		String invalidNameID = prefix + "InvalidNameIDPolicy";
		String noAuthnContext = prefix + "NoAuthnContext";
		String noAvailableIDP = prefix + "NoAvailableIDP";
		String noPassive = prefix + "NoPassive";
		String noSupportedIDP = prefix + "NoSupportedIDP";
		String partialLogout = prefix + "PartialLogout";
		String proxyCountExceeded = prefix + "ProxyCountExceeded";
		String requestDenied = prefix + "RequestDenied";
		String requestUnsupported = prefix + "RequestUnsupported";
		String requestVersionDeprecated = prefix + "RequestVersionDeprecated";
		String requestVersionTooHigh = prefix + "RequestVersionTooHigh";
		String requestVersionTooLow = prefix + "RequestVersionTooLow";
		String resourceNotRecognized = prefix + "ResourceNotRecognized";
		String tooManyResponse = prefix + "TooManyResponse";
		String unknownAttrProfile = prefix + "UnknownAttrProfile";
		String unkownPrincipal = prefix + "UnknownPrincipal";
		String unsupportedBinding = prefix + "UnsupportedBinding";
		
		AuthnResponseError testObj = null;
		
		testObj = new AuthnResponseError(CODE.REQUESTER, "", "", "");
		Assert.assertEquals(testObj.getStatus(), requester);
		
		testObj = new AuthnResponseError(CODE.RESPONDER, "", "", "");
		Assert.assertEquals(testObj.getStatus(), responder);
		
		testObj = new AuthnResponseError(CODE.VERSION_MISMATCH, "", "", "");
		Assert.assertEquals(testObj.getStatus(), versionMismatch);
		
		testObj = new AuthnResponseError(CODE.AUTHN_FAILED, "", "", "");
		Assert.assertEquals(testObj.getStatus(), authnFailed);
		
		testObj = new AuthnResponseError(CODE.INVALID_ATTR_NAME_OR_VALUE, "", "", "");
		Assert.assertEquals(testObj.getStatus(), invalidAttr);
		
		testObj = new AuthnResponseError(CODE.INVALID_NAME_ID_POLICY, "", "", "");
		Assert.assertEquals(testObj.getStatus(), invalidNameID);
		
		testObj = new AuthnResponseError(CODE.NO_AUTHN_CONTEXT, "", "", "");
		Assert.assertEquals(testObj.getStatus(), noAuthnContext);
		
		testObj = new AuthnResponseError(CODE.NO_AVAILABLE_IDP, "", "", "");
		Assert.assertEquals(testObj.getStatus(), noAvailableIDP);
		
		testObj = new AuthnResponseError(CODE.NO_PASSIV, "", "", "");
		Assert.assertEquals(testObj.getStatus(), noPassive);
		
		testObj = new AuthnResponseError(CODE.NO_SUPPORTED_IDP, "", "", "");
		Assert.assertEquals(testObj.getStatus(), noSupportedIDP);
		
		testObj = new AuthnResponseError(CODE.PARTIAL_LOGOUT, "", "", "");
		Assert.assertEquals(testObj.getStatus(), partialLogout);
		
		testObj = new AuthnResponseError(CODE.PROXY_COUNT_EXCEEDED, "", "", "");
		Assert.assertEquals(testObj.getStatus(), proxyCountExceeded);
		
		testObj = new AuthnResponseError(CODE.REQUEST_DENIED, "", "", "");
		Assert.assertEquals(testObj.getStatus(), requestDenied);
		
		testObj = new AuthnResponseError(CODE.REQUEST_UNSUPPORTED, "", "", "");
		Assert.assertEquals(testObj.getStatus(), requestUnsupported);
		
		testObj = new AuthnResponseError(CODE.REQUEST_VERSION_DEPRECATED, "", "", "");
		Assert.assertEquals(testObj.getStatus(), requestVersionDeprecated);
		
		testObj = new AuthnResponseError(CODE.REQUEST_VERSION_TOO_HIGH, "", "", "");
		Assert.assertEquals(testObj.getStatus(), requestVersionTooHigh);
		
		testObj = new AuthnResponseError(CODE.REQUEST_VERSION_TOO_LOW, "", "", "");
		Assert.assertEquals(testObj.getStatus(), requestVersionTooLow);
		
		testObj = new AuthnResponseError(CODE.RESOURCE_NOT_RECOGNIZED, "", "", "");
		Assert.assertEquals(testObj.getStatus(), resourceNotRecognized);
		
		testObj = new AuthnResponseError(CODE.TOO_MANY_RESPONSE, "", "", "");
		Assert.assertEquals(testObj.getStatus(), tooManyResponse);
		
		testObj = new AuthnResponseError(CODE.UNKNOWN_ATTR_PROFILE, "", "", "");
		Assert.assertEquals(testObj.getStatus(), unknownAttrProfile);
		
		testObj = new AuthnResponseError(CODE.UNKNOWN_PRINCIPAL, "", "", "");
		Assert.assertEquals(testObj.getStatus(), unkownPrincipal);
		
		testObj = new AuthnResponseError(CODE.UNSUPPORTED_BINDING, "", "", "");
		Assert.assertEquals(testObj.getStatus(), unsupportedBinding);
		
	}
}
