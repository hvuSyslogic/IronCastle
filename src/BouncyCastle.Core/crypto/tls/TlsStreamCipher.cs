namespace org.bouncycastle.crypto.tls
{

	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;

	public class TlsStreamCipher : TlsCipher
	{
		protected internal TlsContext context;

		protected internal StreamCipher encryptCipher;
		protected internal StreamCipher decryptCipher;

		protected internal TlsMac writeMac;
		protected internal TlsMac readMac;

		protected internal bool usesNonce;

		public TlsStreamCipher(TlsContext context, StreamCipher clientWriteCipher, StreamCipher serverWriteCipher, Digest clientWriteDigest, Digest serverWriteDigest, int cipherKeySize, bool usesNonce)
		{
			bool isServer = context.isServer();

			this.context = context;
			this.usesNonce = usesNonce;

			this.encryptCipher = clientWriteCipher;
			this.decryptCipher = serverWriteCipher;

			int key_block_size = (2 * cipherKeySize) + clientWriteDigest.getDigestSize() + serverWriteDigest.getDigestSize();

			byte[] key_block = TlsUtils.calculateKeyBlock(context, key_block_size);

			int offset = 0;

			// Init MACs
			TlsMac clientWriteMac = new TlsMac(context, clientWriteDigest, key_block, offset, clientWriteDigest.getDigestSize());
			offset += clientWriteDigest.getDigestSize();
			TlsMac serverWriteMac = new TlsMac(context, serverWriteDigest, key_block, offset, serverWriteDigest.getDigestSize());
			offset += serverWriteDigest.getDigestSize();

			// Build keys
			KeyParameter clientWriteKey = new KeyParameter(key_block, offset, cipherKeySize);
			offset += cipherKeySize;
			KeyParameter serverWriteKey = new KeyParameter(key_block, offset, cipherKeySize);
			offset += cipherKeySize;

			if (offset != key_block_size)
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			CipherParameters encryptParams, decryptParams;
			if (isServer)
			{
				this.writeMac = serverWriteMac;
				this.readMac = clientWriteMac;
				this.encryptCipher = serverWriteCipher;
				this.decryptCipher = clientWriteCipher;
				encryptParams = serverWriteKey;
				decryptParams = clientWriteKey;
			}
			else
			{
				this.writeMac = clientWriteMac;
				this.readMac = serverWriteMac;
				this.encryptCipher = clientWriteCipher;
				this.decryptCipher = serverWriteCipher;
				encryptParams = clientWriteKey;
				decryptParams = serverWriteKey;
			}

			if (usesNonce)
			{
				byte[] dummyNonce = new byte[8];
				encryptParams = new ParametersWithIV(encryptParams, dummyNonce);
				decryptParams = new ParametersWithIV(decryptParams, dummyNonce);
			}

			this.encryptCipher.init(true, encryptParams);
			this.decryptCipher.init(false, decryptParams);
		}

		public virtual int getPlaintextLimit(int ciphertextLimit)
		{
			return ciphertextLimit - writeMac.getSize();
		}

		public virtual byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
		{
			if (usesNonce)
			{
				updateIV(encryptCipher, true, seqNo);
			}

			byte[] outBuf = new byte[len + writeMac.getSize()];

			encryptCipher.processBytes(plaintext, offset, len, outBuf, 0);

			byte[] mac = writeMac.calculateMac(seqNo, type, plaintext, offset, len);
			encryptCipher.processBytes(mac, 0, mac.Length, outBuf, len);

			return outBuf;
		}

		public virtual byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
		{
			if (usesNonce)
			{
				updateIV(decryptCipher, false, seqNo);
			}

			int macSize = readMac.getSize();
			if (len < macSize)
			{
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}

			int plaintextLength = len - macSize;

			byte[] deciphered = new byte[len];
			decryptCipher.processBytes(ciphertext, offset, len, deciphered, 0);
			checkMAC(seqNo, type, deciphered, plaintextLength, len, deciphered, 0, plaintextLength);
			return Arrays.copyOfRange(deciphered, 0, plaintextLength);
		}

		public virtual void checkMAC(long seqNo, short type, byte[] recBuf, int recStart, int recEnd, byte[] calcBuf, int calcOff, int calcLen)
		{
			byte[] receivedMac = Arrays.copyOfRange(recBuf, recStart, recEnd);
			byte[] computedMac = readMac.calculateMac(seqNo, type, calcBuf, calcOff, calcLen);

			if (!Arrays.constantTimeAreEqual(receivedMac, computedMac))
			{
				throw new TlsFatalAlert(AlertDescription.bad_record_mac);
			}
		}

		public virtual void updateIV(StreamCipher cipher, bool forEncryption, long seqNo)
		{
			byte[] nonce = new byte[8];
			TlsUtils.writeUint64(seqNo, nonce, 0);
			cipher.init(forEncryption, new ParametersWithIV(null, nonce));
		}
	}

}