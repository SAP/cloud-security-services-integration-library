/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.mtls;

import java.io.EOFException;
import java.io.IOException;
import java.math.BigInteger;

class MinimalDERParser {
	private static final String INVALID_LENGTH_ENCODING = "Invalid length encoding";
	private byte[] content;
	private int idx;

	public MinimalDERParser(byte[] content) {
		this.content = content;
	}

	public int getSequence() throws IOException {
		ensureTag(0x30);
		return readLength();
	}

	public BigInteger getBigInteger() throws IOException {
		ensureTag(0x02);
		return new BigInteger(extractBytes(readLength()));
	}

	private byte[] extractBytes(int numBytes) throws IOException {
		ensureRemainingSize(numBytes);
		byte[] tmp = new byte[numBytes];
		System.arraycopy(content, idx, tmp, 0, numBytes);
		idx += numBytes;
		return tmp;
	}

	private void ensureRemainingSize(int size) throws IOException {
		ensure(size > 0, INVALID_LENGTH_ENCODING);
		if (idx + size > content.length) {
			throw new EOFException();
		}
	}

	private void ensure(boolean condition, String message) throws IOException {
		if (!condition) {
			throw new IOException(message);
		}
	}

	private int readLength() throws IOException {
		int length = nextByte();

		ensure(length != 256, INVALID_LENGTH_ENCODING);

		if (length <= 127) {
			return length; // one byte length form
		}

		length -= 128;// length described in #bytes
		if (length == 0) {
			return -1; // length undefined
		}

		ensure(length < 4, INVALID_LENGTH_ENCODING);

		int totalLength = 0;
		for (int i = 0; i < length; ++i) {
			totalLength = totalLength * 256 + nextByte();
			ensure(totalLength > 0, INVALID_LENGTH_ENCODING);
		}

		return totalLength;
	}

	private void ensureTag(int tag) throws IOException {
		int next = nextByte();
		if (next != tag) {
			throw new IOException(String.format("Expected tag 0x%2x but 0x%2x found", tag, next));
		}
	}

	private int nextByte() throws IOException {
		ensureRemainingSize(1);
		return content[idx++] & 0xFF;
	}

}