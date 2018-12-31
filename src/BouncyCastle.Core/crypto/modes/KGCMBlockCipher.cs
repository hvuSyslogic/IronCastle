using org.bouncycastle.crypto.modes.kgcm;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.modes
{

									
	/// <summary>
	/// Implementation of DSTU7624 GCM mode
	/// </summary>
	public class KGCMBlockCipher : AEADBlockCipher
	{
		private bool InstanceFieldsInitialized = false;

		private void InitializeInstanceFields()
		{
			associatedText = new ExposedByteArrayOutputStream(this);
			data = new ExposedByteArrayOutputStream(this);
		}

		private const int MIN_MAC_BITS = 64;

		private static KGCMMultiplier createDefaultMultiplier(int blockSize)
		{
			switch (blockSize)
			{
			case 16:
				return new Tables4kKGCMMultiplier_128();
			case 32:
				return new Tables8kKGCMMultiplier_256();
			case 64:
				return new Tables16kKGCMMultiplier_512();
			default:
				throw new IllegalArgumentException("Only 128, 256, and 512 -bit block sizes supported");
			}
		}

		private BlockCipher engine;
		private BufferedBlockCipher ctrEngine;

		private int macSize;
		private bool forEncryption;

		private byte[] initialAssociatedText;
		private byte[] macBlock;
		private byte[] iv;

		private KGCMMultiplier multiplier;
		private ulong[] b;

		private readonly int blockSize;

		private ExposedByteArrayOutputStream associatedText;
		private ExposedByteArrayOutputStream data;

		public KGCMBlockCipher(BlockCipher dstu7624Engine)
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
			this.engine = dstu7624Engine;
			this.ctrEngine = new BufferedBlockCipher(new KCTRBlockCipher(this.engine));
			this.macSize = -1;
			this.blockSize = engine.getBlockSize();

			this.initialAssociatedText = new byte[blockSize];
			this.iv = new byte[blockSize];
			this.multiplier = createDefaultMultiplier(blockSize);
			this.b = new ulong[(blockSize >> 3)];

			this.macBlock = null;
		}

		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			this.forEncryption = forEncryption;

			KeyParameter engineParam;
			if (@params is AEADParameters)
			{
				AEADParameters param = (AEADParameters)@params;

				byte[] iv = param.getNonce();
				int diff = this.iv.Length - iv.Length;
				Arrays.fill(this.iv, 0);
				JavaSystem.arraycopy(iv, 0, this.iv, diff, iv.Length);

				initialAssociatedText = param.getAssociatedText();

				int macSizeBits = param.getMacSize();
				if (macSizeBits < MIN_MAC_BITS || macSizeBits > (blockSize << 3) || (macSizeBits & 7) != 0)
				{
					throw new IllegalArgumentException("Invalid value for MAC size: " + macSizeBits);
				}

				macSize = (int)((uint)macSizeBits >> 3);
				engineParam = param.getKey();

				if (initialAssociatedText != null)
				{
					processAADBytes(initialAssociatedText, 0, initialAssociatedText.Length);
				}
			}
			else if (@params is ParametersWithIV)
			{
				ParametersWithIV param = (ParametersWithIV)@params;

				byte[] iv = param.getIV();
				int diff = this.iv.Length - iv.Length;
				Arrays.fill(this.iv, 0);
				JavaSystem.arraycopy(iv, 0, this.iv, diff, iv.Length);

				initialAssociatedText = null;

				macSize = blockSize; // Set default mac size

				engineParam = (KeyParameter)param.getParameters();
			}
			else
			{
				throw new IllegalArgumentException("Invalid parameter passed");
			}

			// TODO Nonce re-use check (sample code from GCMBlockCipher)
	//        if (forEncryption)
	//        {
	//            if (nonce != null && Arrays.areEqual(nonce, newNonce))
	//            {
	//                if (keyParam == null)
	//                {
	//                    throw new IllegalArgumentException("cannot reuse nonce for GCM encryption");
	//                }
	//                if (lastKey != null && Arrays.areEqual(lastKey, keyParam.getKey()))
	//                {
	//                    throw new IllegalArgumentException("cannot reuse nonce for GCM encryption");
	//                }
	//            }
	//        }

			this.macBlock = new byte[blockSize];
			ctrEngine.init(true, new ParametersWithIV(engineParam, this.iv));
			engine.init(true, engineParam);
		}

		public virtual string getAlgorithmName()
		{
			return engine.getAlgorithmName() + "/KGCM";
		}

		public virtual BlockCipher getUnderlyingCipher()
		{
			return engine;
		}

		public virtual void processAADByte(byte @in)
		{
			associatedText.write(@in);
		}

		public virtual void processAADBytes(byte[] @in, int inOff, int len)
		{
			associatedText.write(@in, inOff, len);
		}

		private void processAAD(byte[] authText, int authOff, int len)
		{
			int pos = authOff, end = authOff + len;
			while (pos < end)
			{
				xorWithInput(b, authText, pos);
				multiplier.multiplyH(b);
				pos += blockSize;
			}
		}

		public virtual int processByte(byte @in, byte[] @out, int outOff)
		{
			data.write(@in);

			return 0;
		}

		public virtual int processBytes(byte[] @in, int inOff, int inLen, byte[] @out, int outOff)
		{
			if (@in.Length < (inOff + inLen))
			{
				throw new DataLengthException("input buffer too short");
			}

			data.write(@in, inOff, inLen);

			return 0;
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			int len = data.size();
			if (!forEncryption && len < macSize)
			{
				throw new InvalidCipherTextException("data too short");
			}

			// TODO Total blocks restriction in GCM mode (extend limit naturally for larger block sizes?)

			{
			// Set up the multiplier
				byte[] temp = new byte[blockSize];
				engine.processBlock(temp, 0, temp, 0);
				ulong[] H = new ulong[(blockSize >> 3)];
				Pack.littleEndianToULong(temp, 0, H);
				multiplier.init(H);
				Arrays.fill(temp, 0);
				Arrays.fill(H, 0L);
			}

			int lenAAD = associatedText.size();
			if (lenAAD > 0)
			{
				processAAD(associatedText.getBuffer(), 0, lenAAD);
			}

			//use alternative cipher to produce output
			int resultLen;
			if (forEncryption)
			{
				if (@out.Length - outOff - macSize < len)
				{
					throw new OutputLengthException("Output buffer too short");
				}

				resultLen = ctrEngine.processBytes(data.getBuffer(), 0, len, @out, outOff);
				resultLen += ctrEngine.doFinal(@out, outOff + resultLen);

				calculateMac(@out, outOff, len, lenAAD);
			}
			else
			{
				int ctLen = len - macSize;
				if (@out.Length - outOff < ctLen)
				{
					throw new OutputLengthException("Output buffer too short");
				}

				calculateMac(data.getBuffer(), 0, ctLen, lenAAD);

				resultLen = ctrEngine.processBytes(data.getBuffer(), 0, ctLen, @out, outOff);
				resultLen += ctrEngine.doFinal(@out, outOff + resultLen);
			}

			if (macBlock == null)
			{
				throw new IllegalStateException("mac is not calculated");
			}

			if (forEncryption)
			{
				JavaSystem.arraycopy(macBlock, 0, @out, outOff + resultLen, macSize);

				reset();

				return resultLen + macSize;
			}
			else
			{
				byte[] mac = new byte[macSize];
				JavaSystem.arraycopy(data.getBuffer(), len - macSize, mac, 0, macSize);

				byte[] calculatedMac = new byte[macSize];
				JavaSystem.arraycopy(macBlock, 0, calculatedMac, 0, macSize);

				if (!Arrays.constantTimeAreEqual(mac, calculatedMac))
				{
					throw new InvalidCipherTextException("mac verification failed");
				}

				reset();

				return resultLen;
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
			return 0;
		}

		public virtual int getOutputSize(int len)
		{
			int totalData = len + data.size();

			if (forEncryption)
			{
				return totalData + macSize;
			}

			return totalData < macSize ? 0 : totalData - macSize;
		}

		public virtual void reset()
		{
			Arrays.fill(b, 0L);

			engine.reset();

			data.reset();
			associatedText.reset();

			if (initialAssociatedText != null)
			{
				processAADBytes(initialAssociatedText, 0, initialAssociatedText.Length);
			}
		}

		private void calculateMac(byte[] input, int inOff, int len, int lenAAD)
		{
			int pos = inOff, end = inOff + len;
			while (pos < end)
			{
				xorWithInput(b, input, pos);
				multiplier.multiplyH(b);
				pos += blockSize;
			}

			ulong lambda_o = ((uint)lenAAD ) << 3;
			ulong lambda_c = ((uint)len) << 3;

	//        byte[] temp = new byte[blockSize];
	//        Pack.longToLittleEndian(lambda_o, temp, 0);
	//        Pack.longToLittleEndian(lambda_c, temp, blockSize / 2);
	//
	//        xorWithInput(b, temp, 0);
			b[0] ^= lambda_o;
			b[(blockSize >> 4)] ^= lambda_c;

			macBlock = Pack.ulongToLittleEndian(b);
			engine.processBlock(macBlock, 0, macBlock, 0);
		}

		private static void xorWithInput(ulong[] z, byte[] buf, int off)
		{
			for (int i = 0; i < z.Length; ++i)
			{
				z[i] ^= Pack.littleEndianToULong(buf, off);
				off += 8;
			}
		}

		public class ExposedByteArrayOutputStream : ByteArrayOutputStream
		{
			private readonly KGCMBlockCipher outerInstance;

			public ExposedByteArrayOutputStream(KGCMBlockCipher outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public virtual byte[] getBuffer()
			{
				return this.buf;
			}
		}
	}

}