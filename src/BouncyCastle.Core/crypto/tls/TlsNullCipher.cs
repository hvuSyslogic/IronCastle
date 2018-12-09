﻿using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.tls
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// A NULL CipherSuite with optional MAC
	/// </summary>
	public class TlsNullCipher : TlsCipher
	{
		protected internal TlsContext context;

		protected internal TlsMac writeMac;
		protected internal TlsMac readMac;

		public TlsNullCipher(TlsContext context)
		{
			this.context = context;
			this.writeMac = null;
			this.readMac = null;
		}

		public TlsNullCipher(TlsContext context, Digest clientWriteDigest, Digest serverWriteDigest)
		{
			if ((clientWriteDigest == null) != (serverWriteDigest == null))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			this.context = context;

			TlsMac clientWriteMac = null, serverWriteMac = null;

			if (clientWriteDigest != null)
			{
				int key_block_size = clientWriteDigest.getDigestSize() + serverWriteDigest.getDigestSize();
				byte[] key_block = TlsUtils.calculateKeyBlock(context, key_block_size);

				int offset = 0;

				clientWriteMac = new TlsMac(context, clientWriteDigest, key_block, offset, clientWriteDigest.getDigestSize());
				offset += clientWriteDigest.getDigestSize();

				serverWriteMac = new TlsMac(context, serverWriteDigest, key_block, offset, serverWriteDigest.getDigestSize());
				offset += serverWriteDigest.getDigestSize();

				if (offset != key_block_size)
				{
					throw new TlsFatalAlert(AlertDescription.internal_error);
				}
			}

			if (context.isServer())
			{
				writeMac = serverWriteMac;
				readMac = clientWriteMac;
			}
			else
			{
				writeMac = clientWriteMac;
				readMac = serverWriteMac;
			}
		}

		public virtual int getPlaintextLimit(int ciphertextLimit)
		{
			int result = ciphertextLimit;
			if (writeMac != null)
			{
				result -= writeMac.getSize();
			}
			return result;
		}

		public virtual byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
		{
			if (writeMac == null)
			{
				return Arrays.copyOfRange(plaintext, offset, offset + len);
			}

			byte[] mac = writeMac.calculateMac(seqNo, type, plaintext, offset, len);
			byte[] ciphertext = new byte[len + mac.Length];
			JavaSystem.arraycopy(plaintext, offset, ciphertext, 0, len);
			JavaSystem.arraycopy(mac, 0, ciphertext, len, mac.Length);
			return ciphertext;
		}

		public virtual byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
		{
			if (readMac == null)
			{
				return Arrays.copyOfRange(ciphertext, offset, offset + len);
			}

			int macSize = readMac.getSize();
			if (len < macSize)
			{
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}

			int macInputLen = len - macSize;

			byte[] receivedMac = Arrays.copyOfRange(ciphertext, offset + macInputLen, offset + len);
			byte[] computedMac = readMac.calculateMac(seqNo, type, ciphertext, offset, macInputLen);

			if (!Arrays.constantTimeAreEqual(receivedMac, computedMac))
			{
				throw new TlsFatalAlert(AlertDescription.bad_record_mac);
			}

			return Arrays.copyOfRange(ciphertext, offset, offset + macInputLen);
		}
	}

}