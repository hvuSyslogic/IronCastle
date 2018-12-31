using System;
using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.signers
{

	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using ParametersWithSalt = org.bouncycastle.crypto.@params.ParametersWithSalt;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// ISO9796-2 - mechanism using a hash function with recovery (scheme 2 and 3).
	/// <para>
	/// Note: the usual length for the salt is the length of the hash
	/// function used in bytes.
	/// </para>
	/// </summary>
	public class ISO9796d2PSSSigner : SignerWithRecovery
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

		private Digest digest;
		private AsymmetricBlockCipher cipher;

		private SecureRandom random;
		private byte[] standardSalt;

		private int hLen;
		private int trailer;
		private int keyBits;
		private byte[] block;
		private byte[] mBuf;
		private int messageLength;
		private int saltLength;
		private bool fullMessage;
		private byte[] recoveredMessage;

		private byte[] preSig;
		private byte[] preBlock;
		private int preMStart;
		private int preTLength;

		/// <summary>
		/// Generate a signer with either implicit or explicit trailers for ISO9796-2, scheme 2 or 3.
		/// </summary>
		/// <param name="cipher">     base cipher to use for signature creation/verification </param>
		/// <param name="digest">     digest to use. </param>
		/// <param name="saltLength"> length of salt in bytes. </param>
		/// <param name="implicit">   whether or not the trailer is implicit or gives the hash. </param>
		public ISO9796d2PSSSigner(AsymmetricBlockCipher cipher, Digest digest, int saltLength, bool @implicit)
		{
			this.cipher = cipher;
			this.digest = digest;
			this.hLen = digest.getDigestSize();
			this.saltLength = saltLength;

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
		/// <param name="cipher">     cipher to use. </param>
		/// <param name="digest">     digest to sign with. </param>
		/// <param name="saltLength"> length of salt in bytes. </param>
		public ISO9796d2PSSSigner(AsymmetricBlockCipher cipher, Digest digest, int saltLength) : this(cipher, digest, saltLength, false)
		{
		}

		/// <summary>
		/// Initialise the signer.
		/// </summary>
		/// <param name="forSigning"> true if for signing, false if for verification. </param>
		/// <param name="param">      parameters for signature generation/verification. If the
		///                   parameters are for generation they should be a ParametersWithRandom,
		///                   a ParametersWithSalt, or just an RSAKeyParameters object. If RSAKeyParameters
		///                   are passed in a SecureRandom will be created. </param>
		/// <exception cref="IllegalArgumentException"> if wrong parameter type or a fixed
		/// salt is passed in which is the wrong length. </exception>
		public virtual void init(bool forSigning, CipherParameters param)
		{
			RSAKeyParameters kParam;
			int lengthOfSalt = saltLength;

			if (param is ParametersWithRandom)
			{
				ParametersWithRandom p = (ParametersWithRandom)param;

				kParam = (RSAKeyParameters)p.getParameters();
				if (forSigning)
				{
					random = p.getRandom();
				}
			}
			else if (param is ParametersWithSalt)
			{
				ParametersWithSalt p = (ParametersWithSalt)param;

				kParam = (RSAKeyParameters)p.getParameters();
				standardSalt = p.getSalt();
				lengthOfSalt = standardSalt.Length;
				if (standardSalt.Length != saltLength)
				{
					throw new IllegalArgumentException("Fixed salt is of wrong length");
				}
			}
			else
			{
				kParam = (RSAKeyParameters)param;
				if (forSigning)
				{
					random = CryptoServicesRegistrar.getSecureRandom();
				}
			}

			cipher.init(forSigning, kParam);

			keyBits = kParam.getModulus().bitLength();

			block = new byte[(keyBits + 7) / 8];

			if (trailer == ISOTrailers.TRAILER_IMPLICIT)
			{
				mBuf = new byte[block.Length - digest.getDigestSize() - lengthOfSalt - 1 - 1];
			}
			else
			{
				mBuf = new byte[block.Length - digest.getDigestSize() - lengthOfSalt - 1 - 2];
			}

			reset();
		}

		/// <summary>
		/// compare two byte arrays - constant time
		/// </summary>
		private bool isSameAs(byte[] a, byte[] b)
		{
			bool isOkay = true;

			if (messageLength != b.Length)
			{
				isOkay = false;
			}

			for (int i = 0; i != b.Length; i++)
			{
				if (a[i] != b[i])
				{
					isOkay = false;
				}
			}

			return isOkay;
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

		public virtual void updateWithRecoveredMessage(byte[] signature)
		{
			byte[] block = cipher.processBlock(signature, 0, signature.Length);

			//
			// adjust block size for leading zeroes if necessary
			//
			if (block.Length < (keyBits + 7) / 8)
			{
				byte[] tmp = new byte[(keyBits + 7) / 8];

				JavaSystem.arraycopy(block, 0, tmp, tmp.Length - block.Length, block.Length);
				clearBlock(block);
				block = tmp;
			}

			int tLength;

			if (((block[block.Length - 1] & 0xFF) ^ 0xBC) == 0)
			{
				tLength = 1;
			}
			else
			{
				int sigTrail = ((block[block.Length - 2] & 0xFF) << 8) | (block[block.Length - 1] & 0xFF);

				int? trailerObj = ISOTrailers.getTrailer(digest);

				if (trailerObj != null)
				{
					int trailer = trailerObj.Value;
					if (sigTrail != trailer)
					{
						if (!(trailer == ISOTrailers.TRAILER_SHA512_256 && sigTrail == 0x40CC))
						{
							throw new IllegalStateException("signer initialised with wrong digest for trailer " + sigTrail);
						}
					}
				}
				else
				{
					throw new IllegalArgumentException("unrecognised hash in signature");
				}

				tLength = 2;
			}

			//
			// calculate H(m2)
			//
			byte[] m2Hash = new byte[hLen];
			digest.doFinal(m2Hash, 0);

			//
			// remove the mask
			//
			byte[] dbMask = maskGeneratorFunction1(block, block.Length - hLen - tLength, hLen, block.Length - hLen - tLength);
			for (int i = 0; i != dbMask.Length; i++)
			{
				block[i] ^= dbMask[i];
			}

			block[0] &= 0x7f;

			//
			// find out how much padding we've got
			//
			int mStart = 0;
			for (; mStart != block.Length; mStart++)
			{
				if (block[mStart] == 0x01)
				{
					break;
				}
			}

			mStart++;

			if (mStart >= block.Length)
			{
				clearBlock(block);
			}

			fullMessage = (mStart > 1);

			recoveredMessage = new byte[dbMask.Length - mStart - saltLength];

			JavaSystem.arraycopy(block, mStart, recoveredMessage, 0, recoveredMessage.Length);
			JavaSystem.arraycopy(recoveredMessage, 0, mBuf, 0, recoveredMessage.Length);

			preSig = signature;
			preBlock = block;
			preMStart = mStart;
			preTLength = tLength;
		}

		/// <summary>
		/// update the internal digest with the byte b
		/// </summary>
		public virtual void update(byte b)
		{
			if (preSig == null && messageLength < mBuf.Length)
			{
				mBuf[messageLength++] = b;
			}
			else
			{
				digest.update(b);
			}
		}

		/// <summary>
		/// update the internal digest with the byte array in
		/// </summary>
		public virtual void update(byte[] @in, int off, int len)
		{
			if (preSig == null)
			{
				while (len > 0 && messageLength < mBuf.Length)
				{
					this.update(@in[off]);
					off++;
					len--;
				}
			}

			if (len > 0)
			{
				digest.update(@in, off, len);
			}
		}

		/// <summary>
		/// reset the internal state
		/// </summary>
		public virtual void reset()
		{
			digest.reset();
			messageLength = 0;
			if (mBuf != null)
			{
				clearBlock(mBuf);
			}
			if (recoveredMessage != null)
			{
				clearBlock(recoveredMessage);
				recoveredMessage = null;
			}
			fullMessage = false;
			if (preSig != null)
			{
				preSig = null;
				clearBlock(preBlock);
				preBlock = null;
			}
		}

		/// <summary>
		/// generate a signature for the loaded message using the key we were
		/// initialised with.
		/// </summary>
		public virtual byte[] generateSignature()
		{
			int digSize = digest.getDigestSize();

			byte[] m2Hash = new byte[digSize];

			digest.doFinal(m2Hash, 0);

			byte[] C = new byte[8];
			LtoOSP(messageLength * 8, C);

			digest.update(C, 0, C.Length);

			digest.update(mBuf, 0, messageLength);

			digest.update(m2Hash, 0, m2Hash.Length);

			byte[] salt;

			if (standardSalt != null)
			{
				salt = standardSalt;
			}
			else
			{
				salt = new byte[saltLength];
				random.nextBytes(salt);
			}

			digest.update(salt, 0, salt.Length);

			byte[] hash = new byte[digest.getDigestSize()];

			digest.doFinal(hash, 0);

			int tLength = 2;
			if (trailer == ISOTrailers.TRAILER_IMPLICIT)
			{
				tLength = 1;
			}

			int off = block.Length - messageLength - salt.Length - hLen - tLength - 1;

			block[off] = 0x01;

			JavaSystem.arraycopy(mBuf, 0, block, off + 1, messageLength);
			JavaSystem.arraycopy(salt, 0, block, off + 1 + messageLength, salt.Length);

			byte[] dbMask = maskGeneratorFunction1(hash, 0, hash.Length, block.Length - hLen - tLength);
			for (int i = 0; i != dbMask.Length; i++)
			{
				block[i] ^= dbMask[i];
			}

			JavaSystem.arraycopy(hash, 0, block, block.Length - hLen - tLength, hLen);

			if (trailer == ISOTrailers.TRAILER_IMPLICIT)
			{
				block[block.Length - 1] = ISOTrailers.TRAILER_IMPLICIT;
			}
			else
			{
				block[block.Length - 2] = (byte)((int)((uint)trailer >> 8));
				block[block.Length - 1] = (byte)trailer;
			}

			block[0] &= 0x7f;

			byte[] b = cipher.processBlock(block, 0, block.Length);

			recoveredMessage = new byte[messageLength];

			fullMessage = (messageLength <= mBuf.Length);
			JavaSystem.arraycopy(mBuf, 0, recoveredMessage, 0, recoveredMessage.Length);

			clearBlock(mBuf);
			clearBlock(block);
			messageLength = 0;

			return b;
		}

		/// <summary>
		/// return true if the signature represents a ISO9796-2 signature
		/// for the passed in message.
		/// </summary>
		public virtual bool verifySignature(byte[] signature)
		{
			//
			// calculate H(m2)
			//
			byte[] m2Hash = new byte[hLen];
			digest.doFinal(m2Hash, 0);

			byte[] block;
			int tLength;
			int mStart = 0;

			if (preSig == null)
			{
				try
				{
					updateWithRecoveredMessage(signature);
				}
				catch (Exception)
				{
					return false;
				}
			}
			else
			{
				if (!Arrays.areEqual(preSig, signature))
				{
					throw new IllegalStateException("updateWithRecoveredMessage called on different signature");
				}
			}

			block = preBlock;
			mStart = preMStart;
			tLength = preTLength;

			preSig = null;
			preBlock = null;

			//
			// check the hashes
			//
			byte[] C = new byte[8];
			LtoOSP(recoveredMessage.Length * 8, C);

			digest.update(C, 0, C.Length);

			if (recoveredMessage.Length != 0)
			{
				digest.update(recoveredMessage, 0, recoveredMessage.Length);
			}

			digest.update(m2Hash, 0, m2Hash.Length);

			// Update for the salt
			if (standardSalt != null)
			{
				digest.update(standardSalt, 0, standardSalt.Length);
			}
			else
			{
				digest.update(block, mStart + recoveredMessage.Length, saltLength);
			}

			byte[] hash = new byte[digest.getDigestSize()];
			digest.doFinal(hash, 0);

			int off = block.Length - tLength - hash.Length;

			bool isOkay = true;

			for (int i = 0; i != hash.Length; i++)
			{
				if (hash[i] != block[off + i])
				{
					isOkay = false;
				}
			}

			clearBlock(block);
			clearBlock(hash);

			if (!isOkay)
			{
				fullMessage = false;
				messageLength = 0;
				clearBlock(recoveredMessage);
				return false;
			}

			//
			// if they've input a message check what we've recovered against
			// what was input.
			//
			if (messageLength != 0)
			{
				if (!isSameAs(mBuf, recoveredMessage))
				{
					messageLength = 0;
					clearBlock(mBuf);
					return false;
				}

			}

			messageLength = 0;

			clearBlock(mBuf);
			return true;
		}

		/// <summary>
		/// Return true if the full message was recoveredMessage.
		/// </summary>
		/// <returns> true on full message recovery, false otherwise, or if not sure. </returns>
		/// <seealso cref= org.bouncycastle.crypto.SignerWithRecovery#hasFullMessage() </seealso>
		public virtual bool hasFullMessage()
		{
			return fullMessage;
		}


		/// <summary>
		/// Return a reference to the recoveredMessage message, either as it was added
		/// to a just generated signature, or extracted from a verified one.
		/// </summary>
		/// <returns> the full/partial recoveredMessage message. </returns>
		/// <seealso cref= org.bouncycastle.crypto.SignerWithRecovery#getRecoveredMessage() </seealso>
		public virtual byte[] getRecoveredMessage()
		{
			return recoveredMessage;
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
		/// long to octet string.
		/// </summary>
		private void LtoOSP(long l, byte[] sp)
		{
			sp[0] = (byte)((long)((ulong)l >> 56));
			sp[1] = (byte)((long)((ulong)l >> 48));
			sp[2] = (byte)((long)((ulong)l >> 40));
			sp[3] = (byte)((long)((ulong)l >> 32));
			sp[4] = (byte)((long)((ulong)l >> 24));
			sp[5] = (byte)((long)((ulong)l >> 16));
			sp[6] = (byte)((long)((ulong)l >> 8));
			sp[7] = (byte)((long)((ulong)l >> 0));
		}

		/// <summary>
		/// mask generator function, as described in PKCS1v2.
		/// </summary>
		private byte[] maskGeneratorFunction1(byte[] Z, int zOff, int zLen, int length)
		{
			byte[] mask = new byte[length];
			byte[] hashBuf = new byte[hLen];
			byte[] C = new byte[4];
			int counter = 0;

			digest.reset();

			while (counter < (length / hLen))
			{
				ItoOSP(counter, C);

				digest.update(Z, zOff, zLen);
				digest.update(C, 0, C.Length);
				digest.doFinal(hashBuf, 0);

				JavaSystem.arraycopy(hashBuf, 0, mask, counter * hLen, hLen);

				counter++;
			}

			if ((counter * hLen) < length)
			{
				ItoOSP(counter, C);

				digest.update(Z, zOff, zLen);
				digest.update(C, 0, C.Length);
				digest.doFinal(hashBuf, 0);

				JavaSystem.arraycopy(hashBuf, 0, mask, counter * hLen, mask.Length - (counter * hLen));
			}

			return mask;
		}
	}

}