using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.encodings
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// this does your basic PKCS 1 v1.5 padding - whether or not you should be using this
	/// depends on your application - see PKCS1 Version 2 for details.
	/// </summary>
	public class PKCS1Encoding : AsymmetricBlockCipher
	{
		/// @deprecated use NOT_STRICT_LENGTH_ENABLED_PROPERTY 
		public const string STRICT_LENGTH_ENABLED_PROPERTY = "org.bouncycastle.pkcs1.strict";

		/// <summary>
		/// some providers fail to include the leading zero in PKCS1 encoded blocks. If you need to
		/// work with one of these set the system property org.bouncycastle.pkcs1.not_strict to true.
		/// <para>
		/// The system property is checked during construction of the encoding object, it is set to
		/// false by default.
		/// </para>
		/// </summary>
		public const string NOT_STRICT_LENGTH_ENABLED_PROPERTY = "org.bouncycastle.pkcs1.not_strict";

		private const int HEADER_LENGTH = 10;

		private SecureRandom random;
		private AsymmetricBlockCipher engine;
		private bool forEncryption;
		private bool forPrivateKey;
		private bool useStrictLength;
		private int pLen = -1;
		private byte[] fallback = null;
		private byte[] blockBuffer;

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="cipher"> </param>
		public PKCS1Encoding(AsymmetricBlockCipher cipher)
		{
			this.engine = cipher;
			this.useStrictLength = useStrict();
		}

		/// <summary>
		/// Constructor for decryption with a fixed plaintext length.
		/// </summary>
		/// <param name="cipher"> The cipher to use for cryptographic operation. </param>
		/// <param name="pLen">   Length of the expected plaintext. </param>
		public PKCS1Encoding(AsymmetricBlockCipher cipher, int pLen)
		{
			this.engine = cipher;
			this.useStrictLength = useStrict();
			this.pLen = pLen;
		}

		/// <summary>
		/// Constructor for decryption with a fixed plaintext length and a fallback
		/// value that is returned, if the padding is incorrect.
		/// </summary>
		/// <param name="cipher">   The cipher to use for cryptographic operation. </param>
		/// <param name="fallback"> The fallback value, we don't do an arraycopy here. </param>
		public PKCS1Encoding(AsymmetricBlockCipher cipher, byte[] fallback)
		{
			this.engine = cipher;
			this.useStrictLength = useStrict();
			this.fallback = fallback;
			this.pLen = fallback.Length;
		}


		//
		// for J2ME compatibility
		//
		private bool useStrict()
		{
			// required if security manager has been installed.
			string strict = (string)AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass(this));
			string notStrict = (string)AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass2(this));

			if (!string.ReferenceEquals(notStrict, null))
			{
				return !notStrict.Equals("true");
			}

			return string.ReferenceEquals(strict, null) || strict.Equals("true");
		}

		public class PrivilegedActionAnonymousInnerClass : PrivilegedAction
		{
			private readonly PKCS1Encoding outerInstance;

			public PrivilegedActionAnonymousInnerClass(PKCS1Encoding outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public object run()
			{
				return JavaSystem.getProperty(STRICT_LENGTH_ENABLED_PROPERTY);
			}
		}

		public class PrivilegedActionAnonymousInnerClass2 : PrivilegedAction
		{
			private readonly PKCS1Encoding outerInstance;

			public PrivilegedActionAnonymousInnerClass2(PKCS1Encoding outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public object run()
			{
				return JavaSystem.getProperty(NOT_STRICT_LENGTH_ENABLED_PROPERTY);
			}
		}

		public virtual AsymmetricBlockCipher getUnderlyingCipher()
		{
			return engine;
		}

		public virtual void init(bool forEncryption, CipherParameters param)
		{
			AsymmetricKeyParameter kParam;

			if (param is ParametersWithRandom)
			{
				ParametersWithRandom rParam = (ParametersWithRandom)param;

				this.random = rParam.getRandom();
				kParam = (AsymmetricKeyParameter)rParam.getParameters();
			}
			else
			{
				kParam = (AsymmetricKeyParameter)param;
				if (!kParam.isPrivate() && forEncryption)
				{
					this.random = CryptoServicesRegistrar.getSecureRandom();
				}
			}

			engine.init(forEncryption, param);

			this.forPrivateKey = kParam.isPrivate();
			this.forEncryption = forEncryption;
			this.blockBuffer = new byte[engine.getOutputBlockSize()];

			if (pLen > 0 && fallback == null && random == null)
			{
			   throw new IllegalArgumentException("encoder requires random");
			}
		}

		public virtual int getInputBlockSize()
		{
			int baseBlockSize = engine.getInputBlockSize();

			if (forEncryption)
			{
				return baseBlockSize - HEADER_LENGTH;
			}
			else
			{
				return baseBlockSize;
			}
		}

		public virtual int getOutputBlockSize()
		{
			int baseBlockSize = engine.getOutputBlockSize();

			if (forEncryption)
			{
				return baseBlockSize;
			}
			else
			{
				return baseBlockSize - HEADER_LENGTH;
			}
		}

		public virtual byte[] processBlock(byte[] @in, int inOff, int inLen)
		{
			if (forEncryption)
			{
				return encodeBlock(@in, inOff, inLen);
			}
			else
			{
				return decodeBlock(@in, inOff, inLen);
			}
		}

		private byte[] encodeBlock(byte[] @in, int inOff, int inLen)
		{
			if (inLen > getInputBlockSize())
			{
				throw new IllegalArgumentException("input data too large");
			}

			byte[] block = new byte[engine.getInputBlockSize()];

			if (forPrivateKey)
			{
				block[0] = 0x01; // type code 1

				for (int i = 1; i != block.Length - inLen - 1; i++)
				{
					block[i] = unchecked((byte)0xFF);
				}
			}
			else
			{
				random.nextBytes(block); // random fill

				block[0] = 0x02; // type code 2

				//
				// a zero byte marks the end of the padding, so all
				// the pad bytes must be non-zero.
				//
				for (int i = 1; i != block.Length - inLen - 1; i++)
				{
					while (block[i] == 0)
					{
						block[i] = (byte)random.nextInt();
					}
				}
			}

			block[block.Length - inLen - 1] = 0x00; // mark the end of the padding
			JavaSystem.arraycopy(@in, inOff, block, block.Length - inLen, inLen);

			return engine.processBlock(block, 0, block.Length);
		}

		/// <summary>
		/// Checks if the argument is a correctly PKCS#1.5 encoded Plaintext
		/// for encryption.
		/// </summary>
		/// <param name="encoded"> The Plaintext. </param>
		/// <param name="pLen">    Expected length of the plaintext. </param>
		/// <returns> Either 0, if the encoding is correct, or -1, if it is incorrect. </returns>
		private static int checkPkcs1Encoding(byte[] encoded, int pLen)
		{
			int correct = 0;
			/*
			 * Check if the first two bytes are 0 2
			 */
			correct |= (encoded[0] ^ 2);

			/*
			 * Now the padding check, check for no 0 byte in the padding
			 */
			int plen = encoded.Length - (pLen + 1);

			for (int i = 1; i < plen; i++)
			{
				int tmp = encoded[i];
				tmp |= tmp >> 1;
				tmp |= tmp >> 2;
				tmp |= tmp >> 4;
				correct |= (tmp & 1) - 1;
			}

			/*
			 * Make sure the padding ends with a 0 byte.
			 */
			correct |= encoded[encoded.Length - (pLen + 1)];

			/*
			 * Return 0 or 1, depending on the result.
			 */
			correct |= correct >> 1;
			correct |= correct >> 2;
			correct |= correct >> 4;
			return ~((correct & 1) - 1);
		}


		/// <summary>
		/// Decode PKCS#1.5 encoding, and return a random value if the padding is not correct.
		/// </summary>
		/// <param name="in">    The encrypted block. </param>
		/// <param name="inOff"> Offset in the encrypted block. </param>
		/// <param name="inLen"> Length of the encrypted block. </param>
		///              //<param name="pLen"> Length of the desired output. </param>
		/// <returns> The plaintext without padding, or a random value if the padding was incorrect. </returns>
		/// <exception cref="InvalidCipherTextException"> </exception>
		private byte[] decodeBlockOrRandom(byte[] @in, int inOff, int inLen)
		{
			if (!forPrivateKey)
			{
				throw new InvalidCipherTextException("sorry, this method is only for decryption, not for signing");
			}

			byte[] block = engine.processBlock(@in, inOff, inLen);
			byte[] random;
			if (this.fallback == null)
			{
				random = new byte[this.pLen];
				this.random.nextBytes(random);
			}
			else
			{
				random = fallback;
			}

			byte[] data = (useStrictLength & (block.Length != engine.getOutputBlockSize())) ? blockBuffer : block;

			/*
			 * Check the padding.
			 */
			int correct = PKCS1Encoding.checkPkcs1Encoding(data, this.pLen);

			/*
			 * Now, to a constant time constant memory copy of the decrypted value
			 * or the random value, depending on the validity of the padding.
			 */
			byte[] result = new byte[this.pLen];
			for (int i = 0; i < this.pLen; i++)
			{
				result[i] = (byte)((data[i + (data.Length - pLen)] & (~correct)) | (random[i] & correct));
			}

			Arrays.fill(data, (byte)0);

			return result;
		}

		/// <exception cref="InvalidCipherTextException"> if the decrypted block is not in PKCS1 format. </exception>
		private byte[] decodeBlock(byte[] @in, int inOff, int inLen)
		{
			/*
			 * If the length of the expected plaintext is known, we use a constant-time decryption.
			 * If the decryption fails, we return a random value.
			 */
			if (this.pLen != -1)
			{
				return this.decodeBlockOrRandom(@in, inOff, inLen);
			}

			byte[] block = engine.processBlock(@in, inOff, inLen);
			bool incorrectLength = (useStrictLength & (block.Length != engine.getOutputBlockSize()));

			byte[] data;
			if (block.Length < getOutputBlockSize())
			{
				data = blockBuffer;
			}
			else
			{
				data = block;
			}

			byte type = data[0];

			bool badType;
			if (forPrivateKey)
			{
				badType = (type != 2);
			}
			else
			{
				badType = (type != 1);
			}

			//
			// find and extract the message block.
			//
			int start = findStart(type, data);

			start++; // data should start at the next byte

			if (badType | start < HEADER_LENGTH)
			{
				Arrays.fill(data, (byte)0);
				throw new InvalidCipherTextException("block incorrect");
			}

			// if we get this far, it's likely to be a genuine encoding error
			if (incorrectLength)
			{
				Arrays.fill(data, (byte)0);
				throw new InvalidCipherTextException("block incorrect size");
			}

			byte[] result = new byte[data.Length - start];

			JavaSystem.arraycopy(data, start, result, 0, result.Length);

			return result;
		}

		private int findStart(byte type, byte[] block)
		{
			int start = -1;
			bool padErr = false;

			for (int i = 1; i != block.Length; i++)
			{
				byte pad = block[i];

				if (pad == 0 & start < 0)
				{
					start = i;
				}
				padErr |= (type == 1 & start < 0 & pad != unchecked((byte)0xff));
			}

			if (padErr)
			{
				return -1;
			}

			return start;
		}
	}

}