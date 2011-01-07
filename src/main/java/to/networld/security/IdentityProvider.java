/**
 * identity_provider - to.networld.security
 *
 * Copyright (C) 2010 by Networld Project
 * Written by Alex Oberhauser <oberhauseralex@networld.to>
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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import org.apache.log4j.Logger;

import to.networld.security.common.Keytool;
import to.networld.security.common.XMLSecurity;
import to.networld.security.common.data.ArtifactResolve;
import to.networld.security.common.data.AuthnRequest;
import to.networld.security.common.data.AuthnResponse;
import to.networld.security.common.data.AuthnResponseError;
import to.networld.security.common.data.AuthnResponseError.CODE;
import to.networld.security.common.saml.AuthnContextClasses.AUTH_METHOD;
import to.networld.security.common.saml.NameIDFormat.ID_FORMAT;
import to.networld.security.idp.IdPMessageFactory;
import to.networld.security.sp.SPMessageFactory;

/**
 * @author Alex Oberhauser
 */
public class IdentityProvider  {
	
	private static String issuerIRI = "http://sp.networld.to/SAML2";
	private static String username = "John Doe"; // or UUID.randomUUID().toString();
	
	/**
	 * @param args
	 * @throws IOException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws UnrecoverableEntryException 
	 * @throws KeyStoreException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 */
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableEntryException, InvalidAlgorithmParameterException {
		Logger log = Logger.getLogger(IdentityProvider.class);
		
		XMLSecurity xmlSec = new XMLSecurity(Keytool.class.getResourceAsStream("/keystore.jks"), "v3ryS3cr3t", "idproot", "v3ryS3cr3t");
		
		SPMessageFactory spMsgFactory = SPMessageFactory.getInstance();
		AuthnRequest auth = spMsgFactory.createAuthnRequest(issuerIRI, ID_FORMAT.PERSISTENT);
		log.trace("\n--- BEGIN AuthnRequest ---\n" + auth + "\n--- END AuthnRequest ---\n");
		System.out.println("Issuer      : " + auth.getIssuer());
		System.out.println("Request ID  : " + auth.getRequestID());
		System.out.println("IssueInstant: " + auth.getIssueInstant());
		System.out.println("NameIDFormat: " + auth.getNameIDFormat());
		System.out.println("Allow Create: " + auth.getNameIDAllowCreate());
		System.out.println();
		
		log.trace("\n--- BEGIN X-Form Part ---\n" + spMsgFactory.createXFormSAMLPart(issuerIRI, ID_FORMAT.PERSISTENT) + "\n--- END X-Form Part---\n");
		
		IdPMessageFactory idpMsgFactory = IdPMessageFactory.getInstance();
//		AuthnResponse response = idpMsgFactory.createResponse(xmlSec, username,
//				auth.getRequestID(), 
//				"http://sp.networld.to/SAML2/SSO/POST",
//				"http://sp.networld.to/SAML2",
//				"https://idp.networld.to/SAML2",
//				ID_FORMAT.PERSISTENT, AUTH_METHOD.PASSWORD);
		AuthnResponse response = idpMsgFactory.createResponse(xmlSec, auth, username, 
				"https://idp.networld.to/SAML2",
				ID_FORMAT.PERSISTENT, AUTH_METHOD.PASSWORD);
		
		log.trace("\n--- BEGIN Response ---\n" + response + "\n--- END Response ---\n");
		System.out.println("Issuer       : " + response.getIssuer());
		System.out.println("SessionID    : " + response.getSessionID());
		System.out.println("Response ID  : " + response.getResponseID());
		System.out.println("Assertion ID : " + response.getAssertionID());
		System.out.println("Request ID   : " + response.getRequestID());
		System.out.println("Issue Instant: " + response.getIssueInstant());
		System.out.println("Destination  : " + response.getDestination());
		System.out.println("Name ID      :  '" + response.getNameID() + "' in format: " + response.getNameIDFormat());
		System.out.println("Audience     : " + response.getAudience());
		System.out.println("NotOnOrAfter : " + response.getNotOnOrAfter());
		System.out.println();
		
		log.trace("\n--- BEGIN X-Form Part ---\n" + idpMsgFactory.createXFormSAMLPart(xmlSec, username,
				auth.getRequestID(),
				"http://sp.networld.to/SAML2/SSO/POST", 
				"http://sp.networld.to/SAML2", "https://idp.networld.to/SAML2",
				ID_FORMAT.PERSISTENT, AUTH_METHOD.PASSWORD) 
				+ "\n--- END X-Form Part---\n");
		
		AuthnResponseError errorMessage = new AuthnResponseError(CODE.AUTHN_FAILED, "https://idp.networld.to/SAML2", "http://sp.networld.to/SAML2/SSO/POST", auth.getRequestID());
		log.trace("\n--- BEGIN AuthnResponseError ---\n" + errorMessage + "\n--- END AuthnResponseError---\n");
		System.out.println("Error Status : " + errorMessage.getStatus());
		System.out.println();
		
		ArtifactResolve artResolve = new ArtifactResolve(xmlSec, "http://sp.networld.to", "http://example.org/ArtifactResolve", "some_artifact_test");
		System.out.println(artResolve);
	}

}
