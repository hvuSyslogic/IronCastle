using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{

	using CBCBlockCipherMac = org.bouncycastle.crypto.macs.CBCBlockCipherMac;
	using AEADParameters = org.bouncycastle.crypto.@params.AEADParameters;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Implements the Counter with Cipher Block Chaining mode (CCM) detailed in
	/// NIST Special Publication 800-38C.
	/// <para>
	/// <b>Note</b>: this mode is a packet mode - it needs all the data up front.
	/// </para>
	/// </summary>
	public class CCMBlockCipher : AEADBlockCipher
	{
		private bool InstanceFieldsInitialized = false;

		private void InitializeInstanceFields()
		{
			associatedText = new ExposedByteArrayOutputStream(this);
			data = new ExposedByteArrayOutputStream(this);
		}

		private BlockCipher cipher;
		private int blockSize;
		private bool forEncryption;
		private byte[] nonce;
		private byte[] initialAssociatedText;
		private int macSize;
		private CipherParameters keyParam;
		private byte[] macBlock;
		private ExposedByteArrayOutputStream associatedText;
		private ExposedByteArrayOutputStream data;

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="c"> the block cipher to be used. </param>
		public CCMBlockCipher(BlockCipher c)
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
			this.cipher = c;
			this.blockSize = c.getBlockSize();
			this.macBlock = new byte[blockSize];

			if (blockSize != 16)
			{
				throw new IllegalArgumentException("cipher required with a block size of 16.");
			}
		}

		/// <summary>
		/// return the underlying block cipher that we are wrapping.
		/// </summary>
		/// <returns> the underlying block cipher that we are wrapping. </returns>
		public virtual BlockCipher getUnderlyingCipher()
		{
			return cipher;
		}


		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			this.forEncryption = forEncryption;

			CipherParameters cipherParameters;
			if (@params is AEADParameters)
			{
				AEADParameters param = (AEADParameters)@params;

				nonce = param.getNonce();
				initialAssociatedText = param.getAssociatedText();
				macSize = param.getMacSize() / 8;
				cipherParameters = param.getKey();
			}
			else if (@params is ParametersWithIV)
			{
				ParametersWithIV param = (ParametersWithIV)@params;

				nonce = param.getIV();
				initialAssociatedText = null;
				macSize = macBlock.Length / 2;
				cipherParameters = param.getParameters();
			}
			else
			{
				throw new IllegalArgumentException("invalid parameters passed to CCM: " + @params.GetType().getName());
			}

			// NOTE: Very basic support for key re-use, but no performance gain from it
			if (cipherParameters != null)
			{
				keyParam = cipherParameters;
			}

			if (nonce == null || nonce.Length < 7 || nonce.Length > 13)
			{
				throw new IllegalArgumentException("nonce must have length from 7 to 13 octets");
			}

			reset();
		}

		public virtual string getAlgorithmName()
		{
			return cipher.getAlgorithmName() + "/CCM";
		}

		public virtual void processAADByte(byte @in)
		{
			associatedText.write(@in);
		}

		public virtual void processAADBytes(byte[] @in, int inOff, int len)
		{
			// TODO: Process AAD online
			associatedText.write(@in, inOff, len);
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
				throw new DataLengthException("Input buffer too short");
			}
			data.write(@in, inOff, inLen);

			return 0;
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			int len = processPacket(data.getBuffer(), 0, data.size(), @out, outOff);

			reset();

			return len;
		}

		public virtual void reset()
		{
			cipher.reset();
			associatedText.reset();
			data.reset();
		}

		/// <summary>
		/// Returns a byte array containing the mac calculated as part of the
		/// last encrypt or decrypt operation.
		/// </summary>
		/// <returns> the last mac calculated. </returns>
		public virtual byte[] getMac()
		{
			byte[] mac = new byte[macSize];

			JavaSystem.arraycopy(macBlock, 0, mac, 0, mac.Length);

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

		/// <summary>
		/// Process a packet of data for either CCM decryption or encryption.
		/// </summary>
		/// <param name="in"> data for processing. </param>
		/// <param name="inOff"> offset at which data starts in the input array. </param>
		/// <param name="inLen"> length of the data in the input array. </param>
		/// <returns> a byte array containing the processed input.. </returns>
		/// <exception cref="IllegalStateException"> if the cipher is not appropriately set up. </exception>
		/// <exception cref="InvalidCipherTextException"> if the input data is truncated or the mac check fails. </exception>
		public virtual byte[] processPacket(byte[] @in, int inOff, int inLen)
		{
			byte[] output;

			if (forEncryption)
			{
				output = new byte[inLen + macSize];
			}
			else
			{
				if (inLen < macSize)
				{
					throw new InvalidCipherTextException("data too short");
				}
				output = new byte[inLen - macSize];
			}

			processPacket(@in, inOff, inLen, output, 0);

			return output;
		}

		/// <summary>
		/// Process a packet of data for either CCM decryption or encryption.
		/// </summary>
		/// <param name="in"> data for processing. </param>
		/// <param name="inOff"> offset at which data starts in the input array. </param>
		/// <param name="inLen"> length of the data in the input array. </param>
		/// <param name="output"> output array. </param>
		/// <param name="outOff"> offset into output array to start putting processed bytes. </param>
		/// <returns> the number of bytes added to output. </returns>
		/// <exception cref="IllegalStateException"> if the cipher is not appropriately set up. </exception>
		/// <exception cref="InvalidCipherTextException"> if the input data is truncated or the mac check fails. </exception>
		/// <exception cref="DataLengthException"> if output buffer too short. </exception>
		public virtual int processPacket(byte[] @in, int inOff, int inLen, byte[] output, int outOff)
		{
			// TODO: handle null keyParam (e.g. via RepeatedKeySpec)
			// Need to keep the CTR and CBC Mac parts around and reset
			if (keyParam == null)
			{
				throw new IllegalStateException("CCM cipher unitialized.");
			}

			int n = nonce.Length;
			int q = 15 - n;
			if (q < 4)
			{
				int limitLen = 1 << (8 * q);
				if (inLen >= limitLen)
				{
					throw new IllegalStateException("CCM packet too large for choice of q.");
				}
			}

			byte[] iv = new byte[blockSize];
			iv[0] = (byte)((q - 1) & 0x7);
			JavaSystem.arraycopy(nonce, 0, iv, 1, nonce.Length);

			BlockCipher ctrCipher = new SICBlockCipher(cipher);
			ctrCipher.init(forEncryption, new ParametersWithIV(keyParam, iv));

			int outputLen;
			int inIndex = inOff;
			int outIndex = outOff;

			if (forEncryption)
			{
				outputLen = inLen + macSize;
				if (output.Length < (outputLen + outOff))
				{
					throw new OutputLengthException("Output buffer too short.");
				}

				calculateMac(@in, inOff, inLen, macBlock);

				byte[] encMac = new byte[blockSize];

				ctrCipher.processBlock(macBlock, 0, encMac, 0); // S0

				while (inIndex < (inOff + inLen - blockSize)) // S1...
				{
					ctrCipher.processBlock(@in, inIndex, output, outIndex);
					outIndex += blockSize;
					inIndex += blockSize;
				}

				byte[] block = new byte[blockSize];

				JavaSystem.arraycopy(@in, inIndex, block, 0, inLen + inOff - inIndex);

				ctrCipher.processBlock(block, 0, block, 0);

				JavaSystem.arraycopy(block, 0, output, outIndex, inLen + inOff - inIndex);

				JavaSystem.arraycopy(encMac, 0, output, outOff + inLen, macSize);
			}
			else
			{
				if (inLen < macSize)
				{
					throw new InvalidCipherTextException("data too short");
				}
				outputLen = inLen - macSize;
				if (output.Length < (outputLen + outOff))
				{
					throw new OutputLengthException("Output buffer too short.");
				}

				JavaSystem.arraycopy(@in, inOff + outputLen, macBlock, 0, macSize);

				ctrCipher.processBlock(macBlock, 0, macBlock, 0);

				for (int i = macSize; i != macBlock.Length; i++)
				{
					macBlock[i] = 0;
				}

				while (inIndex < (inOff + outputLen - blockSize))
				{
					ctrCipher.processBlock(@in, inIndex, output, outIndex);
					outIndex += blockSize;
					inIndex += blockSize;
				}

				byte[] block = new byte[blockSize];

				JavaSystem.arraycopy(@in, inIndex, block, 0, outputLen - (inIndex - inOff));

				ctrCipher.processBlock(block, 0, block, 0);

				JavaSystem.arraycopy(block, 0, output, outIndex, outputLen - (inIndex - inOff));

				byte[] calculatedMacBlock = new byte[blockSize];

				calculateMac(output, outOff, outputLen, calculatedMacBlock);

				if (!Arrays.constantTimeAreEqual(macBlock, calculatedMacBlock))
				{
					throw new InvalidCipherTextException("mac check in CCM failed");
				}
			}

			return outputLen;
		}

		private int calculateMac(byte[] data, int dataOff, int dataLen, byte[] macBlock)
		{
			Mac cMac = new CBCBlockCipherMac(cipher, macSize * 8);

			cMac.init(keyParam);

			//
			// build b0
			//
			byte[] b0 = new byte[16];

			if (hasAssociatedText())
			{
				b0[0] |= 0x40;
			}

			b0[0] |= (byte)((((cMac.getMacSize() - 2) / 2) & 0x7) << 3);

			b0[0] |= (byte)(((15 - nonce.Length) - 1) & 0x7);

			JavaSystem.arraycopy(nonce, 0, b0, 1, nonce.Length);

			int q = dataLen;
			int count = 1;
			while (q > 0)
			{
				b0[b0.Length - count] = unchecked((byte)(q & 0xff));
				q = (int)((uint)q >> 8);
				count++;
			}

			cMac.update(b0, 0, b0.Length);

			//
			// process associated text
			//
			if (hasAssociatedText())
			{
				int extra;

				int textLength = getAssociatedTextLength();
				if (textLength < ((1 << 16) - (1 << 8)))
				{
					cMac.update((byte)(textLength >> 8));
					cMac.update((byte)textLength);

					extra = 2;
				}
				else // can't go any higher than 2^32
				{
					cMac.update(unchecked((byte)0xff));
					cMac.update(unchecked((byte)0xfe));
					cMac.update((byte)(textLength >> 24));
					cMac.update((byte)(textLength >> 16));
					cMac.update((byte)(textLength >> 8));
					cMac.update((byte)textLength);

					extra = 6;
				}

				if (initialAssociatedText != null)
				{
					cMac.update(initialAssociatedText, 0, initialAssociatedText.Length);
				}
				if (associatedText.size() > 0)
				{
					cMac.update(associatedText.getBuffer(), 0, associatedText.size());
				}

				extra = (extra + textLength) % 16;
				if (extra != 0)
				{
					for (int i = extra; i != 16; i++)
					{
						cMac.update((byte)0x00);
					}
				}
			}

			//
			// add the text
			//
			cMac.update(data, dataOff, dataLen);

			return cMac.doFinal(macBlock, 0);
		}

		private int getAssociatedTextLength()
		{
			return associatedText.size() + ((initialAssociatedText == null) ? 0 : initialAssociatedText.Length);
		}

		private bool hasAssociatedText()
		{
			return getAssociatedTextLength() > 0;
		}

		public class ExposedByteArrayOutputStream : ByteArrayOutputStream
		{
			private readonly CCMBlockCipher outerInstance;

			public ExposedByteArrayOutputStream(CCMBlockCipher outerInstance)
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