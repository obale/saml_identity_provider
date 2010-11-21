/**
 * identity_provider - to.networld.test.security.common
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

package to.networld.test.security.common;

import junit.framework.Assert;

import org.junit.Test;

import to.networld.security.common.Base64Helper;

/**
 * @author Alex Oberhauser
 */
public class TestBase64Helper {
	
	@Test
	public void testBase64ConversionSimple() {
		String exampleString = "This String should be converted to Base64...";
		String exampleBase64 = Base64Helper.convertToBase64(exampleString.getBytes());
		String decodedString = new String(Base64Helper.convertFromBase64(exampleBase64));
		Assert.assertEquals(exampleString, decodedString);
	}
	
}
