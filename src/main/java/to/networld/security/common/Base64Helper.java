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

import org.apache.commons.codec.binary.Base64;

/**
 * @author Alex Oberhauser
 */
public class Base64Helper {
	
	/**
	 * Binary->Base64 conversion
	 * 
	 * @param _binaryData A binary input as byte array.
	 * @return The base64 encoded data as string.
	 */
	public static String convertToBase64(byte []_binaryData) {
		return new String(Base64.encodeBase64(_binaryData));
	}
	
	/**
	 * Base64->Binary conversion
	 * 
	 * @param _base64String The base64 string.
	 * @return The binary byte array representation.
	 */
	public static byte[] convertFromBase64(String _base64String) {
		return Base64.decodeBase64(_base64String.getBytes());
	}
}
