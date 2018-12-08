using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{
	using CMac = org.bouncycastle.crypto.macs.CMac;
	using AEADParameters = org.bouncycastle.crypto.@params.AEADParameters;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// A Two-Pass Authenticated-Encryption Scheme Optimized for Simplicity and
	/// Efficiency - by M. Bellare, P. Rogaway, D. Wagner.
	/// 
	/// http://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf
	/// 
	/// EAX is an AEAD scheme based on CTR and OMAC1/CMAC, that uses a single block
	/// cipher to encrypt and authenticate data. It's on-line (the length of a
	/// message isn't needed to begin processing it), has good performances, it's
	/// simple and provably secure (provided the underlying block cipher is secure).
	/// 
	/// Of course, this implementations is NOT thread-safe.
	/// </summary>
	public class EAXBlockCipher : AEADBlockCipher
	{
		private const byte nTAG = 0x0;

		private const byte hTAG = 0x1;

		private const byte cTAG = 0x2;

		private SICBlockCipher cipher;

		private bool forEncryption;

		private int blockSize;

		private Mac mac;

		private byte[] nonceMac;
		private byte[] associatedTextMac;
		private byte[] macBlock;

		private int macSize;
		private byte[] bufBlock;
		private int bufOff;

		private bool cipherInitialized;
		private byte[] initialAssociatedText;

		/// <summary>
		/// Constructor that accepts an instance of a block cipher engine.
		/// </summary>
		/// <param name="cipher"> the engine to use </param>
		public EAXBlockCipher(BlockCipher cipher)
		{
			blockSize = cipher.getBlockSize();
			mac = new CMac(cipher);
			macBlock = new byte[blockSize];
			associatedTextMac = new byte[mac.getMacSize()];
			nonceMac = new byte[mac.getMacSize()];
			this.cipher = new SICBlockCipher(cipher);
		}

		public virtual string getAlgorithmName()
		{
			return cipher.getUnderlyingCipher().getAlgorithmName() + "/EAX";
		}

		public virtual BlockCipher getUnderlyingCipher()
		{
			return cipher.getUnderlyingCipher();
		}

		public virtual int getBlockSize()
		{
			return cipher.getBlockSize();
		}

		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			this.forEncryption = forEncryption;

			byte[] nonce;
			CipherParameters keyParam;

			if (@params is AEADParameters)
			{
				AEADParameters param = (AEADParameters)@params;

				nonce = param.getNonce();
				initialAssociatedText = param.getAssociatedText();
				macSize = param.getMacSize() / 8;
				keyParam = param.getKey();
			}
			else if (@params is ParametersWithIV)
			{
				ParametersWithIV param = (ParametersWithIV)@params;

				nonce = param.getIV();
				initialAssociatedText = null;
				macSize = mac.getMacSize() / 2;
				keyParam = param.getParameters();
			}
			else
			{
				throw new IllegalArgumentException("invalid parameters passed to EAX");
			}

			bufBlock = new byte[forEncryption ? blockSize : (blockSize + macSize)];

			byte[] tag = new byte[blockSize];

			// Key reuse implemented in CBC mode of underlying CMac
			mac.init(keyParam);

			tag[blockSize - 1] = nTAG;
			mac.update(tag, 0, blockSize);
			mac.update(nonce, 0, nonce.Length);
			mac.doFinal(nonceMac, 0);

			// Same BlockCipher underlies this and the mac, so reuse last key on cipher
			cipher.init(true, new ParametersWithIV(null, nonceMac));

			reset();
		}

		private void initCipher()
		{
			if (cipherInitialized)
			{
				return;
			}

			cipherInitialized = true;

			mac.doFinal(associatedTextMac, 0);

			byte[] tag = new byte[blockSize];
			tag[blockSize - 1] = cTAG;
			mac.update(tag, 0, blockSize);
		}

		private void calculateMac()
		{
			byte[] outC = new byte[blockSize];
			mac.doFinal(outC, 0);

			for (int i = 0; i < macBlock.Length; i++)
			{
				macBlock[i] = (byte)(nonceMac[i] ^ associatedTextMac[i] ^ outC[i]);
			}
		}

		public virtual void reset()
		{
			reset(true);
		}

		private void reset(bool clearMac)
		{
			cipher.reset(); // TODO Redundant since the mac will reset it?
			mac.reset();

			bufOff = 0;
			Arrays.fill(bufBlock, (byte)0);

			if (clearMac)
			{
				Arrays.fill(macBlock, (byte)0);
			}

			byte[] tag = new byte[blockSize];
			tag[blockSize - 1] = hTAG;
			mac.update(tag, 0, blockSize);

			cipherInitialized = false;

			if (initialAssociatedText != null)
			{
			   processAADBytes(initialAssociatedText, 0, initialAssociatedText.Length);
			}
		}

		public virtual void processAADByte(byte @in)
		{
			if (cipherInitialized)
			{
				throw new IllegalStateException("AAD data cannot be added after encryption/decryption processing has begun.");
			}
			mac.update(@in);
		}

		public virtual void processAADBytes(byte[] @in, int inOff, int len)
		{
			if (cipherInitialized)
			{
				throw new IllegalStateException("AAD data cannot be added after encryption/decryption processing has begun.");
			}
			mac.update(@in, inOff, len);
		}

		public virtual int processByte(byte @in, byte[] @out, int outOff)
		{
			initCipher();

			return process(@in, @out, outOff);
		}

		public virtual int processBytes(byte[] @in, int inOff, int len, byte[] @out, int outOff)
		{
			initCipher();

			if (@in.Length < (inOff + len))
			{
				throw new DataLengthException("Input buffer too short");
			}

			int resultLen = 0;

			for (int i = 0; i != len; i++)
			{
				resultLen += process(@in[inOff + i], @out, outOff + resultLen);
			}

			return resultLen;
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			initCipher();

			int extra = bufOff;
			byte[] tmp = new byte[bufBlock.Length];

			bufOff = 0;

			if (forEncryption)
			{
				if (@out.Length < (outOff + extra + macSize))
				{
					throw new OutputLengthException("Output buffer too short");
				}
				cipher.processBlock(bufBlock, 0, tmp, 0);

				JavaSystem.arraycopy(tmp, 0, @out, outOff, extra);

				mac.update(tmp, 0, extra);

				calculateMac();

				JavaSystem.arraycopy(macBlock, 0, @out, outOff + extra, macSize);

				reset(false);

				return extra + macSize;
			}
			else
			{
				if (extra < macSize)
				{
					throw new InvalidCipherTextException("data too short");
				}
				if (@out.Length < (outOff + extra - macSize))
				{
					throw new OutputLengthException("Output buffer too short");
				}
				if (extra > macSize)
				{
					mac.update(bufBlock, 0, extra - macSize);

					cipher.processBlock(bufBlock, 0, tmp, 0);

					JavaSystem.arraycopy(tmp, 0, @out, outOff, extra - macSize);
				}

				calculateMac();

				if (!verifyMac(bufBlock, extra - macSize))
				{
					throw new InvalidCipherTextException("mac check in EAX failed");
				}

				reset(false);

				return extra - macSize;
			}
		}

		public virtual byte[] getMac()
		{
			byte[] mac = new byte[macSize];

			JavaSystem.arraycopy(macBlock, 0, mac, 0, macSize);

			return mac;
		}

		public virtual int getUpdateOutputSize(int len)
		{
			int totalData = len + bufOff;
			if (!forEncryption)
			{
				if (totalData < macSize)
				{
					return 0;
				}
				totalData -= macSize;
			}
			return totalData - totalData % blockSize;
		}

		public virtual int getOutputSize(int len)
		{
			int totalData = len + bufOff;

			if (forEncryption)
			{
				return totalData + macSize;
			}

			return totalData < macSize ? 0 : totalData - macSize;
		}

		private int process(byte b, byte[] @out, int outOff)
		{
			bufBlock[bufOff++] = b;

			if (bufOff == bufBlock.Length)
			{
				if (@out.Length < (outOff + blockSize))
				{
					throw new OutputLengthException("Output buffer is too short");
				}
				// TODO Could move the processByte(s) calls to here
	//            initCipher();

				int size;

				if (forEncryption)
				{
					size = cipher.processBlock(bufBlock, 0, @out, outOff);

					mac.update(@out, outOff, blockSize);
				}
				else
				{
					mac.update(bufBlock, 0, blockSize);

					size = cipher.processBlock(bufBlock, 0, @out, outOff);
				}

				bufOff = 0;
				if (!forEncryption)
				{
					JavaSystem.arraycopy(bufBlock, blockSize, bufBlock, 0, macSize);
					bufOff = macSize;
				}

				return size;
			}

			return 0;
		}

		private bool verifyMac(byte[] mac, int off)
		{
			int nonEqual = 0;

			for (int i = 0; i < macSize; i++)
			{
				nonEqual |= (macBlock[i] ^ mac[off + i]);
			}

			return nonEqual == 0;
		}
	}

}