/**
 * identity_provider - to.networld.security.common
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

package to.networld.security.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * @author Alex Oberhauser
 */
public class XMLSecurity {
	private InputStream keystore = null;
	private String keystorePassword = null;
	private String certAlias = null;
	private String certPassword = null;
	
	private XMLSignatureFactory xmlFactory = null; 
	private X509Certificate pubCert = null;
	private PrivateKey signCert = null;
	private Reference reference = null;
	private SignedInfo signedInfo = null;
	private KeyInfo keyInfo = null;
	
	public XMLSecurity(InputStream _keystore, 
			String _keystorePassword,
			String _certAlias,
			String _certPassword) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, UnrecoverableEntryException, InvalidAlgorithmParameterException {
		this.keystore = _keystore;
		this.keystorePassword = _keystorePassword;
		this.certAlias = _certAlias;
		this.certPassword = _certPassword;
		this.xmlFactory = XMLSignatureFactory.getInstance("DOM");
	}
	
	private void initCertificates() throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, UnrecoverableEntryException {
		Keytool keytool = new Keytool(this.keystore, this.keystorePassword);
		this.signCert = keytool.getPrivateX509Certificate(this.certAlias, this.certPassword);
		this.pubCert = keytool.getX509Certificate(this.certAlias);
	}
	
	private void initReference(String _nodeID) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		DigestMethod digMethod = this.xmlFactory.newDigestMethod(DigestMethod.SHA1, null);
		this.reference = this.xmlFactory.newReference("#" + _nodeID, digMethod,
				Collections.singletonList(this.xmlFactory.newTransform(Transform.ENVELOPED, 
						(TransformParameterSpec) null)), null, null);
	}
	
	private void initSignInfo() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		this.signedInfo = this.xmlFactory.newSignedInfo(this.xmlFactory.newCanonicalizationMethod(
				CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
				this.xmlFactory.newSignatureMethod(SignatureMethod.DSA_SHA1, null),
		     Collections.singletonList(this.reference));
	}
	
	private void initKeyInfo() {
		KeyInfoFactory kif = this.xmlFactory.getKeyInfoFactory();
		List<Object> x509Content = new ArrayList<Object>();
		x509Content.add(this.pubCert.getSubjectX500Principal().getName());
//		x509Content.add(this.pubCert);
		X509Data xd = kif.newX509Data(x509Content);
		this.keyInfo = kif.newKeyInfo(Collections.singletonList(xd));
	}
	
	/**
	 * Signs a subtree of the message with the X.509 certificate of this object.
	 * 
	 * @param _os The output stream that holds the signed message.
	 * @param _authMessage The XML message to sign.
	 * @param _nodeID The ID of the node that should be signed.
	 * @throws SAXException
	 * @throws IOException
	 * @throws ParserConfigurationException
	 * @throws MarshalException
	 * @throws XMLSignatureException
	 * @throws TransformerException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws KeyStoreException
	 * @throws UnrecoverableEntryException
	 * @throws InvalidAlgorithmParameterException
	 */
	public void signDocument(OutputStream _os, String _authMessage, String _nodeID) throws SAXException, IOException, ParserConfigurationException, MarshalException, XMLSignatureException, TransformerException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableEntryException, InvalidAlgorithmParameterException {
		this.initCertificates();
		this.initReference(_nodeID);
		this.initSignInfo();
		this.initKeyInfo();
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		ByteArrayInputStream signMessageIS = new ByteArrayInputStream(_authMessage.getBytes());
		Document doc = dbf.newDocumentBuilder().parse(signMessageIS);
		DOMSignContext dsc = new DOMSignContext(signCert, doc.getDocumentElement());
		XMLSignature signature = this.xmlFactory.newXMLSignature(this.signedInfo, this.keyInfo);
		signature.sign(dsc);
		
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();
		trans.transform(new DOMSource(doc), new StreamResult(_os));
	}
}
