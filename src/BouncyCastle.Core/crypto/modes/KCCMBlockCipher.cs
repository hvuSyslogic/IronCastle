using System;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{

	using AEADParameters = org.bouncycastle.crypto.@params.AEADParameters;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Implementation of DSTU7624 CCM mode
	/// </summary>
	public class KCCMBlockCipher : AEADBlockCipher
	{
		private bool InstanceFieldsInitialized = false;

		private void InitializeInstanceFields()
		{
			associatedText = new ExposedByteArrayOutputStream(this);
			data = new ExposedByteArrayOutputStream(this);
		}


		private const int BYTES_IN_INT = 4;
		private const int BITS_IN_BYTE = 8;

		private const int MAX_MAC_BIT_LENGTH = 512;
		private const int MIN_MAC_BIT_LENGTH = 64;

		private BlockCipher engine;

		private int macSize;
		private bool forEncryption;

		private byte[] initialAssociatedText;
		private byte[] mac;
		private byte[] macBlock;

		private byte[] nonce;

		private byte[] G1;
		private byte[] buffer;

		private byte[] s;
		private byte[] counter;


		private ExposedByteArrayOutputStream associatedText;
		private ExposedByteArrayOutputStream data;


		private int Nb_ = 4;

		private void setNb(int Nb)
		{
			if (Nb == 4 || Nb == 6 || Nb == 8)
			{
				Nb_ = Nb;
			}
			else
			{
				throw new IllegalArgumentException("Nb = 4 is recommended by DSTU7624 but can be changed to only 6 or 8 in this implementation");
			}
		}

		/// <summary>
		/// Base constructor. Nb value is set to 4.
		/// </summary>
		/// <param name="engine"> base cipher to use under CCM. </param>
		public KCCMBlockCipher(BlockCipher engine) : this(engine, 4)
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
		}

		/// <summary>
		/// Constructor allowing Nb configuration.
		/// <para>
		/// Nb is a parameter specified in CCM mode of DSTU7624 standard.
		/// This parameter specifies maximum possible length of input. It should
		/// be calculated as follows: Nb = 1/8 * (-3 + log[2]Nmax) + 1,
		/// where Nmax - length of input message in bits. For practical reasons
		/// Nmax usually less than 4Gb, e.g. for Nmax = 2^32 - 1, Nb = 4.
		/// </para> </summary>
		/// <param name="engine"> base cipher to use under CCM. </param>
		/// <param name="nB"> Nb value to use. </param>
		public KCCMBlockCipher(BlockCipher engine, int nB)
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
			this.engine = engine;
			this.macSize = engine.getBlockSize();
			this.nonce = new byte[engine.getBlockSize()];
			this.initialAssociatedText = new byte[engine.getBlockSize()];
			this.mac = new byte[engine.getBlockSize()];
			this.macBlock = new byte[engine.getBlockSize()];
			this.G1 = new byte[engine.getBlockSize()];
			this.buffer = new byte[engine.getBlockSize()];
			this.s = new byte[engine.getBlockSize()];
			this.counter = new byte[engine.getBlockSize()];
			setNb(nB);
		}

		public virtual void init(bool forEncryption, CipherParameters @params)
		{

			CipherParameters cipherParameters;
			if (@params is AEADParameters)
			{

				AEADParameters parameters = (AEADParameters)@params;

				if (parameters.getMacSize() > MAX_MAC_BIT_LENGTH || parameters.getMacSize() < MIN_MAC_BIT_LENGTH || parameters.getMacSize() % 8 != 0)
				{
					throw new IllegalArgumentException("Invalid mac size specified");
				}

				nonce = parameters.getNonce();
				macSize = parameters.getMacSize() / BITS_IN_BYTE;
				initialAssociatedText = parameters.getAssociatedText();
				cipherParameters = parameters.getKey();
			}
			else if (@params is ParametersWithIV)
			{
				nonce = ((ParametersWithIV)@params).getIV();
				macSize = engine.getBlockSize(); // use default blockSize for MAC if it is not specified
				initialAssociatedText = null;
				cipherParameters = ((ParametersWithIV)@params).getParameters();
			}
			else
			{
				throw new IllegalArgumentException("Invalid parameters specified");
			}

			this.mac = new byte[macSize];
			this.forEncryption = forEncryption;
			engine.init(true, cipherParameters);

			counter[0] = 0x01; // defined in standard

			if (initialAssociatedText != null)
			{
				processAADBytes(initialAssociatedText, 0, initialAssociatedText.Length);
			}
		}

		public virtual string getAlgorithmName()
		{
			return engine.getAlgorithmName() + "/KCCM";
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

		private void processAAD(byte[] assocText, int assocOff, int assocLen, int dataLen)
		{
			if (assocLen - assocOff < engine.getBlockSize())
			{
				throw new IllegalArgumentException("authText buffer too short");
			}
			if (assocLen % engine.getBlockSize() != 0)
			{
				throw new IllegalArgumentException("padding not supported");
			}

			JavaSystem.arraycopy(nonce, 0, G1, 0, nonce.Length - Nb_ - 1);

			intToBytes(dataLen, buffer, 0); // for G1

			JavaSystem.arraycopy(buffer, 0, G1, nonce.Length - Nb_ - 1, BYTES_IN_INT);

			G1[G1.Length - 1] = getFlag(true, macSize);

			engine.processBlock(G1, 0, macBlock, 0);

			intToBytes(assocLen, buffer, 0); // for G2

			if (assocLen <= engine.getBlockSize() - Nb_)
			{
				for (int byteIndex = 0; byteIndex < assocLen; byteIndex++)
				{
					buffer[byteIndex + Nb_] ^= assocText[assocOff + byteIndex];
				}

				for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
				{
					macBlock[byteIndex] ^= buffer[byteIndex];
				}

				engine.processBlock(macBlock, 0, macBlock, 0);

				return;
			}

			for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
			{
				macBlock[byteIndex] ^= buffer[byteIndex];
			}

			engine.processBlock(macBlock, 0, macBlock, 0);

			int authLen = assocLen;
			while (authLen != 0)
			{
				for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
				{
					macBlock[byteIndex] ^= assocText[byteIndex + assocOff];
				}

				engine.processBlock(macBlock, 0, macBlock, 0);

				assocOff += engine.getBlockSize();
				authLen -= engine.getBlockSize();
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

		public virtual int processPacket(byte[] @in, int inOff, int len, byte[] @out, int outOff)
		{
			if (@in.Length - inOff < len)
			{
				throw new DataLengthException("input buffer too short");
			}
			if (@out.Length - outOff < len)
			{
				throw new OutputLengthException("output buffer too short");
			}

			if (associatedText.size() > 0)
			{
				if (forEncryption)
				{
					processAAD(associatedText.getBuffer(), 0, associatedText.size(), data.size());
				}
				else
				{
					processAAD(associatedText.getBuffer(), 0, associatedText.size(), data.size() - macSize);
				}
			}

			if (forEncryption)
			{
				if ((len % engine.getBlockSize()) != 0)
				{
					throw new DataLengthException("partial blocks not supported");
				}

				CalculateMac(@in, inOff, len);
				engine.processBlock(nonce, 0, s, 0);

				int totalLength = len;
				while (totalLength > 0)
				{
					ProcessBlock(@in, inOff, len, @out, outOff);
					totalLength -= engine.getBlockSize();
					inOff += engine.getBlockSize();
					outOff += engine.getBlockSize();
				}

				for (int byteIndex = 0; byteIndex < counter.Length; byteIndex++)
				{
					s[byteIndex] += counter[byteIndex];
				}

				engine.processBlock(s, 0, buffer, 0);

				for (int byteIndex = 0; byteIndex < macSize; byteIndex++)
				{
					@out[outOff + byteIndex] = (byte)(buffer[byteIndex] ^ macBlock[byteIndex]);
				}

				JavaSystem.arraycopy(macBlock, 0, mac, 0, macSize);

				reset();

				return len + macSize;
			}
			else
			{
				if ((len - macSize) % engine.getBlockSize() != 0)
				{
					throw new DataLengthException("partial blocks not supported");
				}

				engine.processBlock(nonce, 0, s, 0);

				int blocks = len / engine.getBlockSize();

				for (int blockNum = 0; blockNum < blocks; blockNum++)
				{
					ProcessBlock(@in, inOff, len, @out, outOff);

					inOff += engine.getBlockSize();
					outOff += engine.getBlockSize();
				}

				if (len > inOff)
				{
					for (int byteIndex = 0; byteIndex < counter.Length; byteIndex++)
					{
						s[byteIndex] += counter[byteIndex];
					}

					engine.processBlock(s, 0, buffer, 0);

					for (int byteIndex = 0; byteIndex < macSize; byteIndex++)
					{
						@out[outOff + byteIndex] = (byte)(buffer[byteIndex] ^ @in[inOff + byteIndex]);
					}
					outOff += macSize;
				}

				for (int byteIndex = 0; byteIndex < counter.Length; byteIndex++)
				{
					s[byteIndex] += counter[byteIndex];
				}

				engine.processBlock(s, 0, buffer, 0);

				JavaSystem.arraycopy(@out, outOff - macSize, buffer, 0, macSize);

				CalculateMac(@out, 0, outOff - macSize);

				JavaSystem.arraycopy(macBlock, 0, mac, 0, macSize);

				byte[] calculatedMac = new byte[macSize];

				JavaSystem.arraycopy(buffer, 0, calculatedMac, 0, macSize);

				if (!Arrays.constantTimeAreEqual(mac, calculatedMac))
				{
					throw new InvalidCipherTextException("mac check failed");
				}

				reset();

				return len - macSize;
			}
		}

		private void ProcessBlock(byte[] input, int inOff, int len, byte[] output, int outOff)
		{

			for (int byteIndex = 0; byteIndex < counter.Length; byteIndex++)
			{
				s[byteIndex] += counter[byteIndex];
			}

			engine.processBlock(s, 0, buffer, 0);

			for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
			{
				output[outOff + byteIndex] = (byte)(buffer[byteIndex] ^ input[inOff + byteIndex]);
			}
		}

		private void CalculateMac(byte[] authText, int authOff, int len)
		{
			int totalLen = len;
			while (totalLen > 0)
			{
				for (int byteIndex = 0; byteIndex < engine.getBlockSize(); byteIndex++)
				{
					macBlock[byteIndex] ^= authText[authOff + byteIndex];
				}

				engine.processBlock(macBlock, 0, macBlock, 0);

				totalLen -= engine.getBlockSize();
				authOff += engine.getBlockSize();
			}
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			int len = processPacket(data.getBuffer(), 0, data.size(), @out, outOff);

			reset();

			return len;
		}

		public virtual byte[] getMac()
		{
			return Arrays.clone(mac);
		}

		public virtual int getUpdateOutputSize(int len)
		{
			return len;
		}

		public virtual int getOutputSize(int len)
		{
			return len + macSize;
		}

		public virtual void reset()
		{
			Arrays.fill(G1, 0);
			Arrays.fill(buffer, 0);
			Arrays.fill(counter, 0);
			Arrays.fill(macBlock, 0);
			counter[0] = 0x01;
			data.reset();
			associatedText.reset();

			if (initialAssociatedText != null)
			{
				processAADBytes(initialAssociatedText, 0, initialAssociatedText.Length);
			}
		}


		private void intToBytes(int num, byte[] outBytes, int outOff)
		{
			outBytes[outOff + 3] = (byte)(num >> 24);
			outBytes[outOff + 2] = (byte)(num >> 16);
			outBytes[outOff + 1] = (byte)(num >> 8);
			outBytes[outOff] = (byte)num;
		}

		private byte getFlag(bool authTextPresents, int macSize)
		{
			StringBuffer flagByte = new StringBuffer();

			if (authTextPresents)
			{
				flagByte.append("1");
			}
			else
			{
				flagByte.append("0");
			}


			switch (macSize)
			{
			case 8:
				flagByte.append("010"); // binary 2
				break;
			case 16:
				flagByte.append("011"); // binary 3
				break;
			case 32:
				flagByte.append("100"); // binary 4
				break;
			case 48:
				flagByte.append("101"); // binary 5
				break;
			case 64:
				flagByte.append("110"); // binary 6
				break;
			}

			string binaryNb = Integer.toBinaryString(Nb_ - 1);
			while (binaryNb.Length < 4)
			{
				binaryNb = (new StringBuffer(binaryNb)).insert(0, "0").ToString();
			}

			flagByte.append(binaryNb);

			return (byte)Convert.ToInt32(flagByte.ToString(), 2);

		}

		public class ExposedByteArrayOutputStream : ByteArrayOutputStream
		{
			private readonly KCCMBlockCipher outerInstance;

			public ExposedByteArrayOutputStream(KCCMBlockCipher outerInstance)
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