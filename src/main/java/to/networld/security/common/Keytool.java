/**
 * identity_provider - to.networld.security.common
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

package to.networld.security.common;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author Alex Oberhauser
 */
public class Keytool {
	private final KeyStore keystore;
	private final InputStream keystoreIS;
	private final String keystorePassword;
	
	public Keytool(InputStream _keystoreIS, String _keystorePassword) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		this.keystoreIS = _keystoreIS;
		this.keystorePassword = _keystorePassword;
		this.keystore = KeyStore.getInstance("JKS");
		this.keystore.load(this.keystoreIS, this.keystorePassword.toCharArray());
	}
	
	/**
	 * To generate such a certificate use for example the following command
	 * from the command line:
	 * 
	 * 		$ keytool -genkeypair -keystore keystore.jks -alias idproot
	 * 
	 * @param _alias The alias of the stored X.509 certificate.
	 * @param _password The password of the stored X.509 certificate.
	 * @return The private X.509 certificate (used for signing)
	 * @throws KeyStoreException 
	 * @throws UnrecoverableEntryException 
	 * @throws NoSuchAlgorithmException 
	 */
	public PrivateKey getPrivateX509Certificate(String _alias, String _password) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) this.keystore.getEntry(_alias,
				new KeyStore.PasswordProtection(_password.toCharArray()));
		return (PrivateKey) keyEntry.getPrivateKey();	
	}
	
	public X509Certificate getX509Certificate(String _alias) throws KeyStoreException {
		return (X509Certificate)this.keystore.getCertificate(_alias);
	}
}