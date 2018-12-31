using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.modes
{

	using AEADParameters = org.bouncycastle.crypto.@params.AEADParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// An implementation of <a href="http://tools.ietf.org/html/rfc7253">RFC 7253 on The OCB
	/// Authenticated-Encryption Algorithm</a>, licensed per:
	/// <para>
	/// <blockquote> <a href="http://www.cs.ucdavis.edu/~rogaway/ocb/license1.pdf">License for
	/// Open-Source Software Implementations of OCB</a> (Jan 9, 2013) &mdash; &ldquo;License 1&rdquo; <br>
	/// Under this license, you are authorized to make, use, and distribute open-source software
	/// implementations of OCB. This license terminates for you if you sue someone over their open-source
	/// software implementation of OCB claiming that you have a patent covering their implementation.
	/// </para>
	/// <para>
	/// This is a non-binding summary of a legal document (the link above). The parameters of the license
	/// are specified in the license document and that document is controlling. </blockquote>
	/// </para>
	/// </summary>
	public class OCBBlockCipher : AEADBlockCipher
	{
		private const int BLOCK_SIZE = 16;

		private BlockCipher hashCipher;
		private BlockCipher mainCipher;

		/*
		 * CONFIGURATION
		 */
		private bool forEncryption;
		private int macSize;
		private byte[] initialAssociatedText;

		/*
		 * KEY-DEPENDENT
		 */
		// NOTE: elements are lazily calculated
		private Vector L;
		private byte[] L_Asterisk, L_Dollar;

		/*
		 * NONCE-DEPENDENT
		 */
		private byte[] KtopInput = null;
		private byte[] Stretch = new byte[24];
		private byte[] OffsetMAIN_0 = new byte[16];

		/*
		 * PER-ENCRYPTION/DECRYPTION
		 */
		private byte[] hashBlock, mainBlock;
		private int hashBlockPos, mainBlockPos;
		private long hashBlockCount, mainBlockCount;
		private byte[] OffsetHASH;
		private byte[] Sum;
		private byte[] OffsetMAIN = new byte[16];
		private byte[] Checksum;

		// NOTE: The MAC value is preserved after doFinal
		private byte[] macBlock;

		public OCBBlockCipher(BlockCipher hashCipher, BlockCipher mainCipher)
		{
			if (hashCipher == null)
			{
				throw new IllegalArgumentException("'hashCipher' cannot be null");
			}
			if (hashCipher.getBlockSize() != BLOCK_SIZE)
			{
				throw new IllegalArgumentException("'hashCipher' must have a block size of " + BLOCK_SIZE);
			}
			if (mainCipher == null)
			{
				throw new IllegalArgumentException("'mainCipher' cannot be null");
			}
			if (mainCipher.getBlockSize() != BLOCK_SIZE)
			{
				throw new IllegalArgumentException("'mainCipher' must have a block size of " + BLOCK_SIZE);
			}

			if (!hashCipher.getAlgorithmName().Equals(mainCipher.getAlgorithmName()))
			{
				throw new IllegalArgumentException("'hashCipher' and 'mainCipher' must be the same algorithm");
			}

			this.hashCipher = hashCipher;
			this.mainCipher = mainCipher;
		}

		public virtual BlockCipher getUnderlyingCipher()
		{
			return mainCipher;
		}

		public virtual string getAlgorithmName()
		{
			return mainCipher.getAlgorithmName() + "/OCB";
		}

		public virtual void init(bool forEncryption, CipherParameters parameters)
		{
			bool oldForEncryption = this.forEncryption;
			this.forEncryption = forEncryption;
			this.macBlock = null;

			KeyParameter keyParameter;

			byte[] N;
			if (parameters is AEADParameters)
			{
				AEADParameters aeadParameters = (AEADParameters)parameters;

				N = aeadParameters.getNonce();
				initialAssociatedText = aeadParameters.getAssociatedText();

				int macSizeBits = aeadParameters.getMacSize();
				if (macSizeBits < 64 || macSizeBits > 128 || macSizeBits % 8 != 0)
				{
					throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
				}

				macSize = macSizeBits / 8;
				keyParameter = aeadParameters.getKey();
			}
			else if (parameters is ParametersWithIV)
			{
				ParametersWithIV parametersWithIV = (ParametersWithIV)parameters;

				N = parametersWithIV.getIV();
				initialAssociatedText = null;
				macSize = 16;
				keyParameter = (KeyParameter)parametersWithIV.getParameters();
			}
			else
			{
				throw new IllegalArgumentException("invalid parameters passed to OCB");
			}

			this.hashBlock = new byte[16];
			this.mainBlock = new byte[forEncryption ? BLOCK_SIZE : (BLOCK_SIZE + macSize)];

			if (N == null)
			{
				N = new byte[0];
			}

			if (N.Length > 15)
			{
				throw new IllegalArgumentException("IV must be no more than 15 bytes");
			}

			/*
			 * KEY-DEPENDENT INITIALISATION
			 */

			if (keyParameter != null)
			{
				// hashCipher always used in forward mode
				hashCipher.init(true, keyParameter);
				mainCipher.init(forEncryption, keyParameter);
				KtopInput = null;
			}
			else if (oldForEncryption != forEncryption)
			{
				throw new IllegalArgumentException("cannot change encrypting state without providing key.");
			}

			this.L_Asterisk = new byte[16];
			hashCipher.processBlock(L_Asterisk, 0, L_Asterisk, 0);

			this.L_Dollar = OCB_double(L_Asterisk);

			this.L = new Vector();
			this.L.addElement(OCB_double(L_Dollar));

			/*
			 * NONCE-DEPENDENT AND PER-ENCRYPTION/DECRYPTION INITIALISATION
			 */

			int bottom = processNonce(N);

			int bits = bottom % 8, bytes = bottom / 8;
			if (bits == 0)
			{
				JavaSystem.arraycopy(Stretch, bytes, OffsetMAIN_0, 0, 16);
			}
			else
			{
				for (int i = 0; i < 16; ++i)
				{
					int b1 = Stretch[bytes] & 0xff;
					int b2 = Stretch[++bytes] & 0xff;
					this.OffsetMAIN_0[i] = (byte)((b1 << bits) | ((int)((uint)b2 >> (8 - bits))));
				}
			}

			this.hashBlockPos = 0;
			this.mainBlockPos = 0;

			this.hashBlockCount = 0;
			this.mainBlockCount = 0;

			this.OffsetHASH = new byte[16];
			this.Sum = new byte[16];
			JavaSystem.arraycopy(this.OffsetMAIN_0, 0, this.OffsetMAIN, 0, 16);
			this.Checksum = new byte[16];

			if (initialAssociatedText != null)
			{
				processAADBytes(initialAssociatedText, 0, initialAssociatedText.Length);
			}
		}

		public virtual int processNonce(byte[] N)
		{
			byte[] nonce = new byte[16];
			JavaSystem.arraycopy(N, 0, nonce, nonce.Length - N.Length, N.Length);
			nonce[0] = (byte)(macSize << 4);
			nonce[15 - N.Length] |= 1;

			int bottom = nonce[15] & 0x3F;
			nonce[15] &= unchecked(0xC0);

			/*
			 * When used with incrementing nonces, the cipher is only applied once every 64 inits.
			 */
			if (KtopInput == null || !Arrays.areEqual(nonce, KtopInput))
			{
				byte[] Ktop = new byte[16];
				KtopInput = nonce;
				hashCipher.processBlock(KtopInput, 0, Ktop, 0);
				JavaSystem.arraycopy(Ktop, 0, Stretch, 0, 16);
				for (int i = 0; i < 8; ++i)
				{
					Stretch[16 + i] = (byte)(Ktop[i] ^ Ktop[i + 1]);
				}
			}

			return bottom;
		}

		public virtual byte[] getMac()
		{
			if (macBlock == null)
			{
				return new byte[macSize];
			}
			return Arrays.clone(macBlock);
		}

		public virtual int getOutputSize(int len)
		{
			int totalData = len + mainBlockPos;
			if (forEncryption)
			{
				return totalData + macSize;
			}
			return totalData < macSize ? 0 : totalData - macSize;
		}

		public virtual int getUpdateOutputSize(int len)
		{
			int totalData = len + mainBlockPos;
			if (!forEncryption)
			{
				if (totalData < macSize)
				{
					return 0;
				}
				totalData -= macSize;
			}
			return totalData - totalData % BLOCK_SIZE;
		}

		public virtual void processAADByte(byte input)
		{
			hashBlock[hashBlockPos] = input;
			if (++hashBlockPos == hashBlock.Length)
			{
				processHashBlock();
			}
		}

		public virtual void processAADBytes(byte[] input, int off, int len)
		{
			for (int i = 0; i < len; ++i)
			{
				hashBlock[hashBlockPos] = input[off + i];
				if (++hashBlockPos == hashBlock.Length)
				{
					processHashBlock();
				}
			}
		}

		public virtual int processByte(byte input, byte[] output, int outOff)
		{
			mainBlock[mainBlockPos] = input;
			if (++mainBlockPos == mainBlock.Length)
			{
				processMainBlock(output, outOff);
				return BLOCK_SIZE;
			}
			return 0;
		}

		public virtual int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
		{
			if (input.Length < (inOff + len))
			{
				throw new DataLengthException("Input buffer too short");
			}
			int resultLen = 0;

			for (int i = 0; i < len; ++i)
			{
				mainBlock[mainBlockPos] = input[inOff + i];
				if (++mainBlockPos == mainBlock.Length)
				{
					processMainBlock(output, outOff + resultLen);
					resultLen += BLOCK_SIZE;
				}
			}

			return resultLen;
		}

		public virtual int doFinal(byte[] output, int outOff)
		{
			/*
			 * For decryption, get the tag from the end of the message
			 */
			byte[] tag = null;
			if (!forEncryption)
			{
				if (mainBlockPos < macSize)
				{
					throw new InvalidCipherTextException("data too short");
				}
				mainBlockPos -= macSize;
				tag = new byte[macSize];
				JavaSystem.arraycopy(mainBlock, mainBlockPos, tag, 0, macSize);
			}

			/*
			 * HASH: Process any final partial block; compute final hash value
			 */
			if (hashBlockPos > 0)
			{
				OCB_extend(hashBlock, hashBlockPos);
				updateHASH(L_Asterisk);
			}

			/*
			 * OCB-ENCRYPT/OCB-DECRYPT: Process any final partial block
			 */
			if (mainBlockPos > 0)
			{
				if (forEncryption)
				{
					OCB_extend(mainBlock, mainBlockPos);
					xor(Checksum, mainBlock);
				}

				xor(OffsetMAIN, L_Asterisk);

				byte[] Pad = new byte[16];
				hashCipher.processBlock(OffsetMAIN, 0, Pad, 0);

				xor(mainBlock, Pad);

				if (output.Length < (outOff + mainBlockPos))
				{
					throw new OutputLengthException("Output buffer too short");
				}
				JavaSystem.arraycopy(mainBlock, 0, output, outOff, mainBlockPos);

				if (!forEncryption)
				{
					OCB_extend(mainBlock, mainBlockPos);
					xor(Checksum, mainBlock);
				}
			}

			/*
			 * OCB-ENCRYPT/OCB-DECRYPT: Compute raw tag
			 */
			xor(Checksum, OffsetMAIN);
			xor(Checksum, L_Dollar);
			hashCipher.processBlock(Checksum, 0, Checksum, 0);
			xor(Checksum, Sum);

			this.macBlock = new byte[macSize];
			JavaSystem.arraycopy(Checksum, 0, macBlock, 0, macSize);

			/*
			 * Validate or append tag and reset this cipher for the next run
			 */
			int resultLen = mainBlockPos;

			if (forEncryption)
			{
				if (output.Length < (outOff + resultLen + macSize))
				{
					throw new OutputLengthException("Output buffer too short");
				}
				// Append tag to the message
				JavaSystem.arraycopy(macBlock, 0, output, outOff + resultLen, macSize);
				resultLen += macSize;
			}
			else
			{
				// Compare the tag from the message with the calculated one
				if (!Arrays.constantTimeAreEqual(macBlock, tag))
				{
					throw new InvalidCipherTextException("mac check in OCB failed");
				}
			}

			reset(false);

			return resultLen;
		}

		public virtual void reset()
		{
			reset(true);
		}

		public virtual void clear(byte[] bs)
		{
			if (bs != null)
			{
				Arrays.fill(bs, 0);
			}
		}

		public virtual byte[] getLSub(int n)
		{
			while (n >= L.size())
			{
				L.addElement(OCB_double((byte[])L.lastElement()));
			}
			return (byte[])L.elementAt(n);
		}

		public virtual void processHashBlock()
		{
			/*
			 * HASH: Process any whole blocks
			 */
			updateHASH(getLSub(OCB_ntz(++hashBlockCount)));
			hashBlockPos = 0;
		}

		public virtual void processMainBlock(byte[] output, int outOff)
		{
			if (output.Length < (outOff + BLOCK_SIZE))
			{
				throw new OutputLengthException("Output buffer too short");
			}

			/*
			 * OCB-ENCRYPT/OCB-DECRYPT: Process any whole blocks
			 */

			if (forEncryption)
			{
				xor(Checksum, mainBlock);
				mainBlockPos = 0;
			}

			xor(OffsetMAIN, getLSub(OCB_ntz(++mainBlockCount)));

			xor(mainBlock, OffsetMAIN);
			mainCipher.processBlock(mainBlock, 0, mainBlock, 0);
			xor(mainBlock, OffsetMAIN);

			JavaSystem.arraycopy(mainBlock, 0, output, outOff, 16);

			if (!forEncryption)
			{
				xor(Checksum, mainBlock);
				JavaSystem.arraycopy(mainBlock, BLOCK_SIZE, mainBlock, 0, macSize);
				mainBlockPos = macSize;
			}
		}

		public virtual void reset(bool clearMac)
		{
			hashCipher.reset();
			mainCipher.reset();

			clear(hashBlock);
			clear(mainBlock);

			hashBlockPos = 0;
			mainBlockPos = 0;

			hashBlockCount = 0;
			mainBlockCount = 0;

			clear(OffsetHASH);
			clear(Sum);
			JavaSystem.arraycopy(OffsetMAIN_0, 0, OffsetMAIN, 0, 16);
			clear(Checksum);

			if (clearMac)
			{
				macBlock = null;
			}

			if (initialAssociatedText != null)
			{
				processAADBytes(initialAssociatedText, 0, initialAssociatedText.Length);
			}
		}

		public virtual void updateHASH(byte[] LSub)
		{
			xor(OffsetHASH, LSub);
			xor(hashBlock, OffsetHASH);
			hashCipher.processBlock(hashBlock, 0, hashBlock, 0);
			xor(Sum, hashBlock);
		}

		protected internal static byte[] OCB_double(byte[] block)
		{
			byte[] result = new byte[16];
			int carry = shiftLeft(block, result);

			/*
			 * NOTE: This construction is an attempt at a constant-time implementation.
			 */
			result[15] ^= (byte)((int)((uint)0x87 >> ((1 - carry) << 3)));

			return result;
		}

		protected internal static void OCB_extend(byte[] block, int pos)
		{
			block[pos] = unchecked(0x80);
			while (++pos < 16)
			{
				block[pos] = 0;
			}
		}

		protected internal static int OCB_ntz(long x)
		{
			if (x == 0)
			{
				return 64;
			}

			int n = 0;
			while ((x & 1L) == 0L)
			{
				++n;
				x = (long)((ulong)x >> 1);
			}
			return n;
		}

		protected internal static int shiftLeft(byte[] block, byte[] output)
		{
			int i = 16;
			int bit = 0;
			while (--i >= 0)
			{
				int b = block[i] & 0xff;
				output[i] = (byte)((b << 1) | bit);
				bit = ((int)((uint)b >> 7)) & 1;
			}
			return bit;
		}

		protected internal static void xor(byte[] block, byte[] val)
		{
			for (int i = 15; i >= 0; --i)
			{
				block[i] ^= val[i];
			}
		}
	}

}