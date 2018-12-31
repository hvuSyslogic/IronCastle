using System;
using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.signers
{

			
	/// <summary>
	/// RSA-PSS as described in PKCS# 1 v 2.1.
	/// <para>
	/// Note: the usual value for the salt length is the number of
	/// bytes in the hash function.
	/// </para>
	/// </summary>
	public class PSSSigner : Signer
	{
		public static readonly byte TRAILER_IMPLICIT = unchecked(0xBC);

		private Digest contentDigest;
		private Digest mgfDigest;
		private AsymmetricBlockCipher cipher;
		private SecureRandom random;

		private int hLen;
		private int mgfhLen;
		private bool sSet;
		private int sLen;
		private int emBits;
		private byte[] salt;
		private byte[] mDash;
		private byte[] block;
		private byte trailer;

		/// <summary>
		/// basic constructor
		/// </summary>
		/// <param name="cipher"> the asymmetric cipher to use. </param>
		/// <param name="digest"> the digest to use. </param>
		/// <param name="sLen"> the length of the salt to use (in bytes). </param>
		public PSSSigner(AsymmetricBlockCipher cipher, Digest digest, int sLen) : this(cipher, digest, sLen, TRAILER_IMPLICIT)
		{
		}

		public PSSSigner(AsymmetricBlockCipher cipher, Digest contentDigest, Digest mgfDigest, int sLen) : this(cipher, contentDigest, mgfDigest, sLen, TRAILER_IMPLICIT)
		{
		}

		public PSSSigner(AsymmetricBlockCipher cipher, Digest digest, int sLen, byte trailer) : this(cipher, digest, digest, sLen, trailer)
		{
		}

		public PSSSigner(AsymmetricBlockCipher cipher, Digest contentDigest, Digest mgfDigest, int sLen, byte trailer)
		{
			this.cipher = cipher;
			this.contentDigest = contentDigest;
			this.mgfDigest = mgfDigest;
			this.hLen = contentDigest.getDigestSize();
			this.mgfhLen = mgfDigest.getDigestSize();
			this.sSet = false;
			this.sLen = sLen;
			this.salt = new byte[sLen];
			this.mDash = new byte[8 + sLen + hLen];
			this.trailer = trailer;
		}

		public PSSSigner(AsymmetricBlockCipher cipher, Digest digest, byte[] salt) : this(cipher, digest, digest, salt, TRAILER_IMPLICIT)
		{
		}

		public PSSSigner(AsymmetricBlockCipher cipher, Digest contentDigest, Digest mgfDigest, byte[] salt) : this(cipher, contentDigest, mgfDigest, salt, TRAILER_IMPLICIT)
		{
		}

		public PSSSigner(AsymmetricBlockCipher cipher, Digest contentDigest, Digest mgfDigest, byte[] salt, byte trailer)
		{
			this.cipher = cipher;
			this.contentDigest = contentDigest;
			this.mgfDigest = mgfDigest;
			this.hLen = contentDigest.getDigestSize();
			this.mgfhLen = mgfDigest.getDigestSize();
			this.sSet = true;
			this.sLen = salt.Length;
			this.salt = salt;
			this.mDash = new byte[8 + sLen + hLen];
			this.trailer = trailer;
		}

		public virtual void init(bool forSigning, CipherParameters param)
		{
			CipherParameters @params;

			if (param is ParametersWithRandom)
			{
				ParametersWithRandom p = (ParametersWithRandom)param;

				@params = p.getParameters();
				random = p.getRandom();
			}
			else
			{
				@params = param;
				if (forSigning)
				{
					random = CryptoServicesRegistrar.getSecureRandom();
				}
			}

			RSAKeyParameters kParam;

			if (@params is RSABlindingParameters)
			{
				kParam = ((RSABlindingParameters)@params).getPublicKey();

				cipher.init(forSigning, param); // pass on random
			}
			else
			{
				kParam = (RSAKeyParameters)@params;

				cipher.init(forSigning, @params);
			}

			emBits = kParam.getModulus().bitLength() - 1;

			if (emBits < (8 * hLen + 8 * sLen + 9))
			{
				throw new IllegalArgumentException("key too small for specified hash and salt lengths");
			}

			block = new byte[(emBits + 7) / 8];

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
			contentDigest.update(b);
		}

		/// <summary>
		/// update the internal digest with the byte array in
		/// </summary>
		public virtual void update(byte[] @in, int off, int len)
		{
			contentDigest.update(@in, off, len);
		}

		/// <summary>
		/// reset the internal state
		/// </summary>
		public virtual void reset()
		{
			contentDigest.reset();
		}

		/// <summary>
		/// generate a signature for the message we've been loaded with using
		/// the key we were initialised with.
		/// </summary>
		public virtual byte[] generateSignature()
		{
			contentDigest.doFinal(mDash, mDash.Length - hLen - sLen);

			if (sLen != 0)
			{
				if (!sSet)
				{
					random.nextBytes(salt);
				}

				JavaSystem.arraycopy(salt, 0, mDash, mDash.Length - sLen, sLen);
			}

			byte[] h = new byte[hLen];

			contentDigest.update(mDash, 0, mDash.Length);

			contentDigest.doFinal(h, 0);

			block[block.Length - sLen - 1 - hLen - 1] = 0x01;
			JavaSystem.arraycopy(salt, 0, block, block.Length - sLen - hLen - 1, sLen);

			byte[] dbMask = maskGeneratorFunction1(h, 0, h.Length, block.Length - hLen - 1);
			for (int i = 0; i != dbMask.Length; i++)
			{
				block[i] ^= dbMask[i];
			}

			block[0] &= (byte)(0xff >> ((block.Length * 8) - emBits));

			JavaSystem.arraycopy(h, 0, block, block.Length - hLen - 1, hLen);

			block[block.Length - 1] = trailer;

			byte[] b = cipher.processBlock(block, 0, block.Length);

			clearBlock(block);

			return b;
		}

		/// <summary>
		/// return true if the internal state represents the signature described
		/// in the passed in array.
		/// </summary>
		public virtual bool verifySignature(byte[] signature)
		{
			contentDigest.doFinal(mDash, mDash.Length - hLen - sLen);

			try
			{
				byte[] b = cipher.processBlock(signature, 0, signature.Length);
				JavaSystem.arraycopy(b, 0, block, block.Length - b.Length, b.Length);
			}
			catch (Exception)
			{
				return false;
			}

			if (block[block.Length - 1] != trailer)
			{
				clearBlock(block);
				return false;
			}

			byte[] dbMask = maskGeneratorFunction1(block, block.Length - hLen - 1, hLen, block.Length - hLen - 1);

			for (int i = 0; i != dbMask.Length; i++)
			{
				block[i] ^= dbMask[i];
			}

			block[0] &= (byte)(0xff >> ((block.Length * 8) - emBits));

			for (int i = 0; i != block.Length - hLen - sLen - 2; i++)
			{
				if (block[i] != 0)
				{
					clearBlock(block);
					return false;
				}
			}

			if (block[block.Length - hLen - sLen - 2] != 0x01)
			{
				clearBlock(block);
				return false;
			}

			if (sSet)
			{
				JavaSystem.arraycopy(salt, 0, mDash, mDash.Length - sLen, sLen);
			}
			else
			{
				JavaSystem.arraycopy(block, block.Length - sLen - hLen - 1, mDash, mDash.Length - sLen, sLen);
			}

			contentDigest.update(mDash, 0, mDash.Length);
			contentDigest.doFinal(mDash, mDash.Length - hLen);

			for (int i = block.Length - hLen - 1, j = mDash.Length - hLen; j != mDash.Length; i++, j++)
			{
				if ((block[i] ^ mDash[j]) != 0)
				{
					clearBlock(mDash);
					clearBlock(block);
					return false;
				}
			}

			clearBlock(mDash);
			clearBlock(block);

			return true;
		}

		/// <summary>
		/// int to octet string.
		/// </summary>
		private void ItoOSP(int i, byte[] sp)
		{
			sp[0] = (byte)((int)((uint)i >> 24));
			sp[1] = (byte)((int)((uint)i >> 16));
			sp[2] = (byte)((int)((uint)i >> 8));
			sp[3] = (byte)((int)((uint)i >> 0));
		}

		/// <summary>
		/// mask generator function, as described in PKCS1v2.
		/// </summary>
		private byte[] maskGeneratorFunction1(byte[] Z, int zOff, int zLen, int length)
		{
			byte[] mask = new byte[length];
			byte[] hashBuf = new byte[mgfhLen];
			byte[] C = new byte[4];
			int counter = 0;

			mgfDigest.reset();

			while (counter < (length / mgfhLen))
			{
				ItoOSP(counter, C);

				mgfDigest.update(Z, zOff, zLen);
				mgfDigest.update(C, 0, C.Length);
				mgfDigest.doFinal(hashBuf, 0);

				JavaSystem.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mgfhLen);

				counter++;
			}

			if ((counter * mgfhLen) < length)
			{
				ItoOSP(counter, C);

				mgfDigest.update(Z, zOff, zLen);
				mgfDigest.update(C, 0, C.Length);
				mgfDigest.doFinal(hashBuf, 0);

				JavaSystem.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mask.Length - (counter * mgfhLen));
			}

			return mask;
		}
	}

}