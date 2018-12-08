using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.signers
{

	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	/// <summary>
	/// X9.31-1998 - signing using a hash.
	/// <para>
	/// The message digest hash, H, is encapsulated to form a byte string as follows
	/// <pre>
	/// EB = 06 || PS || 0xBA || H || TRAILER
	/// </pre>
	/// where PS is a string of bytes all of value 0xBB of length such that |EB|=|n|, and TRAILER is the ISO/IEC 10118 part number† for the digest. The byte string, EB, is converted to an integer value, the message representative, f.
	/// </para>
	/// </summary>
	public class X931Signer : Signer
	{
		/// @deprecated use ISOTrailers 
		public const int TRAILER_IMPLICIT = 0xBC;
		/// @deprecated use ISOTrailers 
		public const int TRAILER_RIPEMD160 = 0x31CC;
		/// @deprecated use ISOTrailers 
		public const int TRAILER_RIPEMD128 = 0x32CC;
		/// @deprecated use ISOTrailers 
		public const int TRAILER_SHA1 = 0x33CC;
		/// @deprecated use ISOTrailers 
		public const int TRAILER_SHA256 = 0x34CC;
		/// @deprecated use ISOTrailers 
		public const int TRAILER_SHA512 = 0x35CC;
		/// @deprecated use ISOTrailers 
		public const int TRAILER_SHA384 = 0x36CC;
		/// @deprecated use ISOTrailers 
		public const int TRAILER_WHIRLPOOL = 0x37CC;
		/// @deprecated use ISOTrailers 
		public const int TRAILER_SHA224 = 0x38CC;

		private Digest digest;
		private AsymmetricBlockCipher cipher;
		private RSAKeyParameters kParam;

		private int trailer;
		private int keyBits;
		private byte[] block;

		/// <summary>
		/// Generate a signer with either implicit or explicit trailers for X9.31
		/// </summary>
		/// <param name="cipher"> base cipher to use for signature creation/verification </param>
		/// <param name="digest"> digest to use. </param>
		/// <param name="implicit"> whether or not the trailer is implicit or gives the hash. </param>
		public X931Signer(AsymmetricBlockCipher cipher, Digest digest, bool @implicit)
		{
			this.cipher = cipher;
			this.digest = digest;

			if (@implicit)
			{
				trailer = ISOTrailers.TRAILER_IMPLICIT;
			}
			else
			{
				int? trailerObj = ISOTrailers.getTrailer(digest);

				if (trailerObj != null)
				{
					trailer = trailerObj.Value;
				}
				else
				{
					throw new IllegalArgumentException("no valid trailer for digest: " + digest.getAlgorithmName());
				}
			}
		}

		/// <summary>
		/// Constructor for a signer with an explicit digest trailer.
		/// </summary>
		/// <param name="cipher"> cipher to use. </param>
		/// <param name="digest"> digest to sign with. </param>
		public X931Signer(AsymmetricBlockCipher cipher, Digest digest) : this(cipher, digest, false)
		{
		}

		public virtual void init(bool forSigning, CipherParameters param)
		{
			kParam = (RSAKeyParameters)param;

			cipher.init(forSigning, kParam);

			keyBits = kParam.getModulus().bitLength();

			block = new byte[(keyBits + 7) / 8];

			reset();
		}

		/// <summary>
		/// clear possible sensitive data
		/// </summary>
		private void clearBlock(byte[] block)
		{
			for (int i = 0; i != block.Length; i++)
			{
				block[i] = 0;
			}
		}

		/// <summary>
		/// update the internal digest with the byte b
		/// </summary>
		public virtual void update(byte b)
		{
			digest.update(b);
		}

		/// <summary>
		/// update the internal digest with the byte array in
		/// </summary>
		public virtual void update(byte[] @in, int off, int len)
		{
			digest.update(@in, off, len);
		}

		/// <summary>
		/// reset the internal state
		/// </summary>
		public virtual void reset()
		{
			digest.reset();
		}

		/// <summary>
		/// generate a signature for the loaded message using the key we were
		/// initialised with.
		/// </summary>
		public virtual byte[] generateSignature()
		{
			createSignatureBlock(trailer);

			BigInteger t = new BigInteger(1, cipher.processBlock(block, 0, block.Length));
			clearBlock(block);

			t = t.min(kParam.getModulus().subtract(t));

			int size = BigIntegers.getUnsignedByteLength(kParam.getModulus());
			return BigIntegers.asUnsignedByteArray(size, t);
		}

		private void createSignatureBlock(int trailer)
		{
			int digSize = digest.getDigestSize();

			int delta;

			if (trailer == ISOTrailers.TRAILER_IMPLICIT)
			{
				delta = block.Length - digSize - 1;
				digest.doFinal(block, delta);
				block[block.Length - 1] = (byte)ISOTrailers.TRAILER_IMPLICIT;
			}
			else
			{
				delta = block.Length - digSize - 2;
				digest.doFinal(block, delta);
				block[block.Length - 2] = (byte)((int)((uint)trailer >> 8));
				block[block.Length - 1] = (byte)trailer;
			}

			block[0] = 0x6b;
			for (int i = delta - 2; i != 0; i--)
			{
				block[i] = unchecked((byte)0xbb);
			}
			block[delta - 1] = unchecked((byte)0xba);
		}

		/// <summary>
		/// return true if the signature represents a X9.31 signature
		/// for the passed in message.
		/// </summary>
		public virtual bool verifySignature(byte[] signature)
		{
			try
			{
				block = cipher.processBlock(signature, 0, signature.Length);
			}
			catch (Exception)
			{
				return false;
			}

			BigInteger t = new BigInteger(1, block);
			BigInteger f;

			if ((t.intValue() & 15) == 12)
			{
				 f = t;
			}
			else
			{
				t = kParam.getModulus().subtract(t);
				if ((t.intValue() & 15) == 12)
				{
					 f = t;
				}
				else
				{
					return false;
				}
			}

			createSignatureBlock(trailer);

			byte[] fBlock = BigIntegers.asUnsignedByteArray(block.Length, f);

			bool rv = Arrays.constantTimeAreEqual(block, fBlock);

			// check for old NIST tool value
			if (trailer == ISOTrailers.TRAILER_SHA512_256 && !rv)
			{
				block[block.Length - 2] = (byte)0x40; // old NIST CAVP tool value
				rv = Arrays.constantTimeAreEqual(block, fBlock);
			}

			clearBlock(block);
			clearBlock(fBlock);

			return rv;
		}
	}

}