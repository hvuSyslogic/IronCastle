using System;

namespace org.bouncycastle.crypto.tls
{
	using LongDigest = org.bouncycastle.crypto.digests.LongDigest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// A generic TLS MAC implementation, acting as an HMAC based on some underlying Digest.
	/// </summary>
	public class TlsMac
	{
		protected internal TlsContext context;
		protected internal byte[] secret;
		protected internal Mac mac;
		protected internal int digestBlockSize;
		protected internal int digestOverhead;
		protected internal int macLength;

		/// <summary>
		/// Generate a new instance of an TlsMac.
		/// </summary>
		/// <param name="context"> the TLS client context </param>
		/// <param name="digest">  The digest to use. </param>
		/// <param name="key">     A byte-array where the key for this MAC is located. </param>
		/// <param name="keyOff">  The number of bytes to skip, before the key starts in the buffer. </param>
		/// <param name="keyLen">  The length of the key. </param>
		public TlsMac(TlsContext context, Digest digest, byte[] key, int keyOff, int keyLen)
		{
			this.context = context;

			KeyParameter keyParameter = new KeyParameter(key, keyOff, keyLen);

			this.secret = Arrays.clone(keyParameter.getKey());

			// TODO This should check the actual algorithm, not rely on the engine type
			if (digest is LongDigest)
			{
				this.digestBlockSize = 128;
				this.digestOverhead = 16;
			}
			else
			{
				this.digestBlockSize = 64;
				this.digestOverhead = 8;
			}

			if (TlsUtils.isSSL(context))
			{
				this.mac = new SSL3Mac(digest);

				// TODO This should check the actual algorithm, not assume based on the digest size
				if (digest.getDigestSize() == 20)
				{
					/*
					 * NOTE: When SHA-1 is used with the SSL 3.0 MAC, the secret + input pad is not
					 * digest block-aligned.
					 */
					this.digestOverhead = 4;
				}
			}
			else
			{
				this.mac = new HMac(digest);

				// NOTE: The input pad for HMAC is always a full digest block
			}

			this.mac.init(keyParameter);

			this.macLength = mac.getMacSize();
			if (context.getSecurityParameters().truncatedHMac)
			{
				this.macLength = Math.Min(this.macLength, 10);
			}
		}

		/// <returns> the MAC write secret </returns>
		public virtual byte[] getMACSecret()
		{
			return this.secret;
		}

		/// <returns> The output length of this MAC. </returns>
		public virtual int getSize()
		{
			return macLength;
		}

		/// <summary>
		/// Calculate the MAC for some given data.
		/// </summary>
		/// <param name="type">    The message type of the message. </param>
		/// <param name="message"> A byte-buffer containing the message. </param>
		/// <param name="offset">  The number of bytes to skip, before the message starts. </param>
		/// <param name="length">  The length of the message. </param>
		/// <returns> A new byte-buffer containing the MAC value. </returns>
		public virtual byte[] calculateMac(long seqNo, short type, byte[] message, int offset, int length)
		{
			ProtocolVersion serverVersion = context.getServerVersion();
			bool isSSL = serverVersion.isSSL();

			byte[] macHeader = new byte[isSSL ? 11 : 13];
			TlsUtils.writeUint64(seqNo, macHeader, 0);
			TlsUtils.writeUint8(type, macHeader, 8);
			if (!isSSL)
			{
				TlsUtils.writeVersion(serverVersion, macHeader, 9);
			}
			TlsUtils.writeUint16(length, macHeader, macHeader.Length - 2);

			mac.update(macHeader, 0, macHeader.Length);
			mac.update(message, offset, length);

			byte[] result = new byte[mac.getMacSize()];
			mac.doFinal(result, 0);
			return truncate(result);
		}

		public virtual byte[] calculateMacConstantTime(long seqNo, short type, byte[] message, int offset, int length, int fullLength, byte[] dummyData)
		{
			/*
			 * Actual MAC only calculated on 'length' bytes...
			 */
			byte[] result = calculateMac(seqNo, type, message, offset, length);

			/*
			 * ...but ensure a constant number of complete digest blocks are processed (as many as would
			 * be needed for 'fullLength' bytes of input).
			 */
			int headerLength = TlsUtils.isSSL(context) ? 11 : 13;

			// How many extra full blocks do we need to calculate?
			int extra = getDigestBlockCount(headerLength + fullLength) - getDigestBlockCount(headerLength + length);

			while (--extra >= 0)
			{
				mac.update(dummyData, 0, digestBlockSize);
			}

			// One more byte in case the implementation is "lazy" about processing blocks
			mac.update(dummyData[0]);
			mac.reset();

			return result;
		}

		public virtual int getDigestBlockCount(int inputLength)
		{
			// NOTE: This calculation assumes a minimum of 1 pad byte
			return (inputLength + digestOverhead) / digestBlockSize;
		}

		public virtual byte[] truncate(byte[] bs)
		{
			if (bs.Length <= macLength)
			{
				return bs;
			}

			return Arrays.copyOf(bs, macLength);
		}
	}

}