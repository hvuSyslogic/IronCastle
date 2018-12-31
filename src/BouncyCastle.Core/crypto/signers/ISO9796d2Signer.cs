using System;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.signers
{
		
	/// <summary>
	/// ISO9796-2 - mechanism using a hash function with recovery (scheme 1)
	/// </summary>
	public class ISO9796d2Signer : SignerWithRecovery
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

		private int trailer;
		private int keyBits;
		private byte[] block;
		private byte[] mBuf;
		private int messageLength;
		private bool fullMessage;
		private byte[] recoveredMessage;

		private byte[] preSig;
		private byte[] preBlock;

		/// <summary>
		/// Generate a signer with either implicit or explicit trailers for ISO9796-2.
		/// </summary>
		/// <param name="cipher"> base cipher to use for signature creation/verification </param>
		/// <param name="digest"> digest to use. </param>
		/// <param name="implicit"> whether or not the trailer is implicit or gives the hash. </param>
		public ISO9796d2Signer(AsymmetricBlockCipher cipher, Digest digest, bool @implicit)
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
		public ISO9796d2Signer(AsymmetricBlockCipher cipher, Digest digest) : this(cipher, digest, false)
		{
		}

		public virtual void init(bool forSigning, CipherParameters param)
		{
			RSAKeyParameters kParam = (RSAKeyParameters)param;

			cipher.init(forSigning, kParam);

			keyBits = kParam.getModulus().bitLength();

			block = new byte[(keyBits + 7) / 8];

			if (trailer == ISOTrailers.TRAILER_IMPLICIT)
			{
				mBuf = new byte[block.Length - digest.getDigestSize() - 2];
			}
			else
			{
				mBuf = new byte[block.Length - digest.getDigestSize() - 3];
			}

			reset();
		}

		/// <summary>
		/// compare two byte arrays - constant time
		/// </summary>
		private bool isSameAs(byte[] a, byte[] b)
		{
			bool isOkay = true;

			if (messageLength > mBuf.Length)
			{
				if (mBuf.Length > b.Length)
				{
					isOkay = false;
				}

				for (int i = 0; i != mBuf.Length; i++)
				{
					if (a[i] != b[i])
					{
						isOkay = false;
					}
				}
			}
			else
			{
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

			if (((block[0] & 0xC0) ^ 0x40) != 0)
			{
				throw new InvalidCipherTextException("malformed signature");
			}

			if (((block[block.Length - 1] & 0xF) ^ 0xC) != 0)
			{
				throw new InvalidCipherTextException("malformed signature");
			}

			int delta = 0;

			if (((block[block.Length - 1] & 0xFF) ^ 0xBC) == 0)
			{
				delta = 1;
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

				delta = 2;
			}

			//
			// find out how much padding we've got
			//
			int mStart = 0;

			for (mStart = 0; mStart != block.Length; mStart++)
			{
				if (((block[mStart] & 0x0f) ^ 0x0a) == 0)
				{
					break;
				}
			}

			mStart++;

			int off = block.Length - delta - digest.getDigestSize();

			//
			// there must be at least one byte of message string
			//
			if ((off - mStart) <= 0)
			{
				throw new InvalidCipherTextException("malformed block");
			}

			//
			// if we contain the whole message as well, check the hash of that.
			//
			if ((block[0] & 0x20) == 0)
			{
				fullMessage = true;

				recoveredMessage = new byte[off - mStart];
				JavaSystem.arraycopy(block, mStart, recoveredMessage, 0, recoveredMessage.Length);
			}
			else
			{
				fullMessage = false;

				recoveredMessage = new byte[off - mStart];
				JavaSystem.arraycopy(block, mStart, recoveredMessage, 0, recoveredMessage.Length);
			}

			preSig = signature;
			preBlock = block;

			digest.update(recoveredMessage, 0, recoveredMessage.Length);
			messageLength = recoveredMessage.Length;
			JavaSystem.arraycopy(recoveredMessage, 0, mBuf, 0, recoveredMessage.Length);
		}

		/// <summary>
		/// update the internal digest with the byte b
		/// </summary>
		public virtual void update(byte b)
		{
			digest.update(b);

			if (messageLength < mBuf.Length)
			{
				mBuf[messageLength] = b;
			}

			messageLength++;
		}

		/// <summary>
		/// update the internal digest with the byte array in
		/// </summary>
		public virtual void update(byte[] @in, int off, int len)
		{
			while (len > 0 && messageLength < mBuf.Length)
			{
				this.update(@in[off]);
				off++;
				len--;
			}

			digest.update(@in, off, len);
			messageLength += len;
		}

		/// <summary>
		/// reset the internal state
		/// </summary>
		public virtual void reset()
		{
			digest.reset();
			messageLength = 0;
			clearBlock(mBuf);

			if (recoveredMessage != null)
			{
				clearBlock(recoveredMessage);
			}

			recoveredMessage = null;
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

			int t = 0;
			int delta = 0;

			if (trailer == ISOTrailers.TRAILER_IMPLICIT)
			{
				t = 8;
				delta = block.Length - digSize - 1;
				digest.doFinal(block, delta);
				block[block.Length - 1] = ISOTrailers.TRAILER_IMPLICIT;
			}
			else
			{
				t = 16;
				delta = block.Length - digSize - 2;
				digest.doFinal(block, delta);
				block[block.Length - 2] = (byte)((int)((uint)trailer >> 8));
				block[block.Length - 1] = (byte)trailer;
			}

			byte header = 0;
			int x = (digSize + messageLength) * 8 + t + 4 - keyBits;

			if (x > 0)
			{
				int mR = messageLength - ((x + 7) / 8);
				header = 0x60;

				delta -= mR;

				JavaSystem.arraycopy(mBuf, 0, block, delta, mR);

				recoveredMessage = new byte[mR];
			}
			else
			{
				header = 0x40;
				delta -= messageLength;

				JavaSystem.arraycopy(mBuf, 0, block, delta, messageLength);

				recoveredMessage = new byte[messageLength];
			}

			if ((delta - 1) > 0)
			{
				for (int i = delta - 1; i != 0; i--)
				{
					block[i] = unchecked(0xbb);
				}
				block[delta - 1] ^= 0x01;
				block[0] = 0x0b;
				block[0] |= header;
			}
			else
			{
				block[0] = 0x0a;
				block[0] |= header;
			}

			byte[] b = cipher.processBlock(block, 0, block.Length);

			fullMessage = (header & 0x20) == 0;
			JavaSystem.arraycopy(mBuf, 0, recoveredMessage, 0, recoveredMessage.Length);

			messageLength = 0;

			clearBlock(mBuf);
			clearBlock(block);

			return b;
		}

		/// <summary>
		/// return true if the signature represents a ISO9796-2 signature
		/// for the passed in message.
		/// </summary>
		public virtual bool verifySignature(byte[] signature)
		{
			byte[] block = null;

			if (preSig == null)
			{
				try
				{
					block = cipher.processBlock(signature, 0, signature.Length);
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

				block = preBlock;

				preSig = null;
				preBlock = null;
			}

			if (((block[0] & 0xC0) ^ 0x40) != 0)
			{
				return returnFalse(block);
			}

			if (((block[block.Length - 1] & 0xF) ^ 0xC) != 0)
			{
				return returnFalse(block);
			}

			int delta = 0;

			if (((block[block.Length - 1] & 0xFF) ^ 0xBC) == 0)
			{
				delta = 1;
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

				delta = 2;
			}

			//
			// find out how much padding we've got
			//
			int mStart = 0;

			for (mStart = 0; mStart != block.Length; mStart++)
			{
				if (((block[mStart] & 0x0f) ^ 0x0a) == 0)
				{
					break;
				}
			}

			mStart++;

			//
			// check the hashes
			//
			byte[] hash = new byte[digest.getDigestSize()];

			int off = block.Length - delta - hash.Length;

			//
			// there must be at least one byte of message string
			//
			if ((off - mStart) <= 0)
			{
				return returnFalse(block);
			}

			//
			// if we contain the whole message as well, check the hash of that.
			//
			if ((block[0] & 0x20) == 0)
			{
				fullMessage = true;

				// check right number of bytes passed in.
				if (messageLength > off - mStart)
				{
					return returnFalse(block);
				}

				digest.reset();
				digest.update(block, mStart, off - mStart);
				digest.doFinal(hash, 0);

				bool isOkay = true;

				for (int i = 0; i != hash.Length; i++)
				{
					block[off + i] ^= hash[i];
					if (block[off + i] != 0)
					{
						isOkay = false;
					}
				}

				if (!isOkay)
				{
					return returnFalse(block);
				}

				recoveredMessage = new byte[off - mStart];
				JavaSystem.arraycopy(block, mStart, recoveredMessage, 0, recoveredMessage.Length);
			}
			else
			{
				fullMessage = false;

				digest.doFinal(hash, 0);

				bool isOkay = true;

				for (int i = 0; i != hash.Length; i++)
				{
					block[off + i] ^= hash[i];
					if (block[off + i] != 0)
					{
						isOkay = false;
					}
				}

				if (!isOkay)
				{
					return returnFalse(block);
				}

				recoveredMessage = new byte[off - mStart];
				JavaSystem.arraycopy(block, mStart, recoveredMessage, 0, recoveredMessage.Length);
			}

			//
			// if they've input a message check what we've recovered against
			// what was input.
			//
			if (messageLength != 0)
			{
				if (!isSameAs(mBuf, recoveredMessage))
				{
					return returnFalse(block);
				}
			}

			clearBlock(mBuf);
			clearBlock(block);

			messageLength = 0;

			return true;
		}

		private bool returnFalse(byte[] block)
		{
			messageLength = 0;

			clearBlock(mBuf);
			clearBlock(block);

			return false;
		}

		/// <summary>
		/// Return true if the full message was recoveredMessage.
		/// </summary>
		/// <returns> true on full message recovery, false otherwise. </returns>
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
	}

}