/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.proxy.auth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;

import javax.servlet.ServletException;

import com.nimbusds.jose.util.Base64;

public class PullSSHKey implements CertificateExtractSubjectAttribute {

	@Override
	public void addSubjects(HashMap<String, String> subjects, X509Certificate[] certs) throws ServletException {
		try {
			byte[] sshKey = this.encodePublicKey((RSAPublicKey) certs[0].getPublicKey());
			String keyAttr = org.apache.commons.codec.binary.Base64.encodeBase64String(sshKey);
			subjects.put("sshpubkey", keyAttr);
		} catch (IOException e) {
			throw new ServletException("Could not extract SSH Key");
		}
	}

	
	// Code pulled from http://stackoverflow.com/questions/3706177/how-to-generate-ssh-compatible-id-rsa-pub-from-java
	private byte[] encodePublicKey(RSAPublicKey key) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		/* encode the "ssh-rsa" string */
		byte[] sshrsa = new byte[] { 0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a' };
		out.write(sshrsa);
		/* Encode the public exponent */
		BigInteger e = key.getPublicExponent();
		byte[] data = e.toByteArray();
		encodeUInt32(data.length, out);
		out.write(data);
		/* Encode the modulus */
		BigInteger m = key.getModulus();
		data = m.toByteArray();
		encodeUInt32(data.length, out);
		out.write(data);
		return out.toByteArray();
	}

	private void encodeUInt32(int value, OutputStream out) throws IOException {
		byte[] tmp = new byte[4];
		tmp[0] = (byte) ((value >>> 24) & 0xff);
		tmp[1] = (byte) ((value >>> 16) & 0xff);
		tmp[2] = (byte) ((value >>> 8) & 0xff);
		tmp[3] = (byte) (value & 0xff);
		out.write(tmp);
	}

}
