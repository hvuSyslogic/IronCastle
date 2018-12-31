using System;
using org.bouncycastle.crypto.macs;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.generators
{
			
	/// <summary>
	/// HMAC-based Extract-and-Expand Key Derivation Function (HKDF) implemented
	/// according to IETF RFC 5869, May 2010 as specified by H. Krawczyk, IBM
	/// Research &amp; P. Eronen, Nokia. It uses a HMac internally to compute de OKM
	/// (output keying material) and is likely to have better security properties
	/// than KDF's based on just a hash function.
	/// </summary>
	public class HKDFBytesGenerator : DerivationFunction
	{

		private HMac hMacHash;
		private int hashLen;

		private byte[] info;
		private byte[] currentT;

		private int generatedBytes;

		/// <summary>
		/// Creates a HKDFBytesGenerator based on the given hash function.
		/// </summary>
		/// <param name="hash"> the digest to be used as the source of generatedBytes bytes </param>
		public HKDFBytesGenerator(Digest hash)
		{
			this.hMacHash = new HMac(hash);
			this.hashLen = hash.getDigestSize();
		}

		public virtual void init(DerivationParameters param)
		{
			if (!(param is HKDFParameters))
			{
				throw new IllegalArgumentException("HKDF parameters required for HKDFBytesGenerator");
			}

			HKDFParameters @params = (HKDFParameters)param;
			if (@params.skipExtract())
			{
				// use IKM directly as PRK
				hMacHash.init(new KeyParameter(@params.getIKM()));
			}
			else
			{
				hMacHash.init(extract(@params.getSalt(), @params.getIKM()));
			}

			info = @params.getInfo();

			generatedBytes = 0;
			currentT = new byte[hashLen];
		}

		/// <summary>
		/// Performs the extract part of the key derivation function.
		/// </summary>
		/// <param name="salt"> the salt to use </param>
		/// <param name="ikm">  the input keying material </param>
		/// <returns> the PRK as KeyParameter </returns>
		private KeyParameter extract(byte[] salt, byte[] ikm)
		{
			if (salt == null)
			{
				// TODO check if hashLen is indeed same as HMAC size
				hMacHash.init(new KeyParameter(new byte[hashLen]));
			}
			else
			{
				hMacHash.init(new KeyParameter(salt));
			}

			hMacHash.update(ikm, 0, ikm.Length);

			byte[] prk = new byte[hashLen];
			hMacHash.doFinal(prk, 0);
			return new KeyParameter(prk);
		}

		/// <summary>
		/// Performs the expand part of the key derivation function, using currentT
		/// as input and output buffer.
		/// </summary>
		/// <exception cref="DataLengthException"> if the total number of bytes generated is larger than the one
		/// specified by RFC 5869 (255 * HashLen) </exception>
		private void expandNext()
		{
			int n = generatedBytes / hashLen + 1;
			if (n >= 256)
			{
				throw new DataLengthException("HKDF cannot generate more than 255 blocks of HashLen size");
			}
			// special case for T(0): T(0) is empty, so no update
			if (generatedBytes != 0)
			{
				hMacHash.update(currentT, 0, hashLen);
			}
			hMacHash.update(info, 0, info.Length);
			hMacHash.update((byte)n);
			hMacHash.doFinal(currentT, 0);
		}

		public virtual Digest getDigest()
		{
			return hMacHash.getUnderlyingDigest();
		}

		public virtual int generateBytes(byte[] @out, int outOff, int len)
		{

			if (generatedBytes + len > 255 * hashLen)
			{
				throw new DataLengthException("HKDF may only be used for 255 * HashLen bytes of output");
			}

			if (generatedBytes % hashLen == 0)
			{
				expandNext();
			}

			// copy what is left in the currentT (1..hash
			int toGenerate = len;
			int posInT = generatedBytes % hashLen;
			int leftInT = hashLen - generatedBytes % hashLen;
			int toCopy = Math.Min(leftInT, toGenerate);
			JavaSystem.arraycopy(currentT, posInT, @out, outOff, toCopy);
			generatedBytes += toCopy;
			toGenerate -= toCopy;
			outOff += toCopy;

			while (toGenerate > 0)
			{
				expandNext();
				toCopy = Math.Min(hashLen, toGenerate);
				JavaSystem.arraycopy(currentT, 0, @out, outOff, toCopy);
				generatedBytes += toCopy;
				toGenerate -= toCopy;
				outOff += toCopy;
			}

			return len;
		}
	}

}