using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Pack = org.bouncycastle.util.Pack;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Implementation of Daniel J. Bernstein's Salsa20 stream cipher, Snuffle 2005
	/// </summary>
	public class Salsa20Engine : SkippingStreamCipher
	{
		public const int DEFAULT_ROUNDS = 20;

		/// <summary>
		/// Constants </summary>
		private const int STATE_SIZE = 16; // 16, 32 bit ints = 64 bytes

		private static readonly int[] TAU_SIGMA = Pack.littleEndianToInt(Strings.toByteArray("expand 16-byte k" + "expand 32-byte k"), 0, 8);

		public virtual void packTauOrSigma(int keyLength, int[] state, int stateOffset)
		{
			int tsOff = (keyLength - 16) / 4;
			state[stateOffset] = TAU_SIGMA[tsOff];
			state[stateOffset + 1] = TAU_SIGMA[tsOff + 1];
			state[stateOffset + 2] = TAU_SIGMA[tsOff + 2];
			state[stateOffset + 3] = TAU_SIGMA[tsOff + 3];
		}

		/// @deprecated 
		protected internal static readonly byte[] sigma = Strings.toByteArray("expand 32-byte k"), tau = Strings.toByteArray("expand 16-byte k");

		protected internal int rounds;

		/*
		 * variables to hold the state of the engine
		 * during encryption and decryption
		 */
		private int index = 0;
		protected internal int[] engineState = new int[STATE_SIZE]; // state
		protected internal int[] x = new int[STATE_SIZE]; // internal buffer
		private byte[] keyStream = new byte[STATE_SIZE * 4]; // expanded state, 64 bytes
		private bool initialised = false;

		/*
		 * internal counter
		 */
		private int cW0, cW1, cW2;

		/// <summary>
		/// Creates a 20 round Salsa20 engine.
		/// </summary>
		public Salsa20Engine() : this(DEFAULT_ROUNDS)
		{
		}

		/// <summary>
		/// Creates a Salsa20 engine with a specific number of rounds. </summary>
		/// <param name="rounds"> the number of rounds (must be an even number). </param>
		public Salsa20Engine(int rounds)
		{
			if (rounds <= 0 || (rounds & 1) != 0)
			{
				throw new IllegalArgumentException("'rounds' must be a positive, even number");
			}

			this.rounds = rounds;
		}

		/// <summary>
		/// initialise a Salsa20 cipher.
		/// </summary>
		/// <param name="forEncryption"> whether or not we are for encryption. </param>
		/// <param name="params"> the parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			/* 
			* Salsa20 encryption and decryption is completely
			* symmetrical, so the 'forEncryption' is 
			* irrelevant. (Like 90% of stream ciphers)
			*/

			if (!(@params is ParametersWithIV))
			{
				throw new IllegalArgumentException(getAlgorithmName() + " Init parameters must include an IV");
			}

			ParametersWithIV ivParams = (ParametersWithIV) @params;

			byte[] iv = ivParams.getIV();
			if (iv == null || iv.Length != getNonceSize())
			{
				throw new IllegalArgumentException(getAlgorithmName() + " requires exactly " + getNonceSize() + " bytes of IV");
			}

			CipherParameters keyParam = ivParams.getParameters();
			if (keyParam == null)
			{
				if (!initialised)
				{
					throw new IllegalStateException(getAlgorithmName() + " KeyParameter can not be null for first initialisation");
				}

				setKey(null, iv);
			}
			else if (keyParam is KeyParameter)
			{
				setKey(((KeyParameter)keyParam).getKey(), iv);
			}
			else
			{
				throw new IllegalArgumentException(getAlgorithmName() + " Init parameters must contain a KeyParameter (or null for re-init)");
			}

			reset();

			initialised = true;
		}

		public virtual int getNonceSize()
		{
			return 8;
		}

		public virtual string getAlgorithmName()
		{
			string name = "Salsa20";
			if (rounds != DEFAULT_ROUNDS)
			{
				name += "/" + rounds;
			}
			return name;
		}

		public virtual byte returnByte(byte @in)
		{
			if (limitExceeded())
			{
				throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
			}

			byte @out = (byte)(keyStream[index] ^ @in);
			index = (index + 1) & 63;

			if (index == 0)
			{
				advanceCounter();
				generateKeyStream(keyStream);
			}

			return @out;
		}

		public virtual void advanceCounter(long diff)
		{
			int hi = (int)((long)((ulong)diff >> 32));
			int lo = (int)diff;

			if (hi > 0)
			{
				engineState[9] += hi;
			}

			int oldState = engineState[8];

			engineState[8] += lo;

			if (oldState != 0 && engineState[8] < oldState)
			{
				engineState[9]++;
			}
		}

		public virtual void advanceCounter()
		{
			if (++engineState[8] == 0)
			{
				++engineState[9];
			}
		}

		public virtual void retreatCounter(long diff)
		{
			int hi = (int)((long)((ulong)diff >> 32));
			int lo = (int)diff;

			if (hi != 0)
			{
				if ((engineState[9] & 0xffffffffL) >= (hi & 0xffffffffL))
				{
					engineState[9] -= hi;
				}
				else
				{
					throw new IllegalStateException("attempt to reduce counter past zero.");
				}
			}

			if ((engineState[8] & 0xffffffffL) >= (lo & 0xffffffffL))
			{
				engineState[8] -= lo;
			}
			else
			{
				if (engineState[9] != 0)
				{
					--engineState[9];
					engineState[8] -= lo;
				}
				else
				{
					throw new IllegalStateException("attempt to reduce counter past zero.");
				}
			}
		}

		public virtual void retreatCounter()
		{
			if (engineState[8] == 0 && engineState[9] == 0)
			{
				throw new IllegalStateException("attempt to reduce counter past zero.");
			}

			if (--engineState[8] == -1)
			{
				--engineState[9];
			}
		}

		public virtual int processBytes(byte[] @in, int inOff, int len, byte[] @out, int outOff)
		{
			if (!initialised)
			{
				throw new IllegalStateException(getAlgorithmName() + " not initialised");
			}

			if ((inOff + len) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + len) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			if (limitExceeded(len))
			{
				throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
			}

			for (int i = 0; i < len; i++)
			{
				@out[i + outOff] = (byte)(keyStream[index] ^ @in[i + inOff]);
				index = (index + 1) & 63;

				if (index == 0)
				{
					advanceCounter();
					generateKeyStream(keyStream);
				}
			}

			return len;
		}

		public virtual long skip(long numberOfBytes)
		{
			if (numberOfBytes >= 0)
			{
				long remaining = numberOfBytes;

				if (remaining >= 64)
				{
					long count = remaining / 64;

					advanceCounter(count);

					remaining -= count * 64;
				}

				int oldIndex = index;

				index = (index + (int)remaining) & 63;

				if (index < oldIndex)
				{
					advanceCounter();
				}
			}
			else
			{
				long remaining = -numberOfBytes;

				if (remaining >= 64)
				{
					long count = remaining / 64;

					retreatCounter(count);

					remaining -= count * 64;
				}

				for (long i = 0; i < remaining; i++)
				{
					if (index == 0)
					{
						retreatCounter();
					}

					index = (index - 1) & 63;
				}
			}

			generateKeyStream(keyStream);

			return numberOfBytes;
		}

		public virtual long seekTo(long position)
		{
			reset();

			return skip(position);
		}

		public virtual long getPosition()
		{
			return getCounter() * 64 + index;
		}

		public virtual void reset()
		{
			index = 0;
			resetLimitCounter();
			resetCounter();

			generateKeyStream(keyStream);
		}

		public virtual long getCounter()
		{
			return ((long)engineState[9] << 32) | (engineState[8] & 0xffffffffL);
		}

		public virtual void resetCounter()
		{
			engineState[8] = engineState[9] = 0;
		}

		public virtual void setKey(byte[] keyBytes, byte[] ivBytes)
		{
			if (keyBytes != null)
			{
				if ((keyBytes.Length != 16) && (keyBytes.Length != 32))
				{
					throw new IllegalArgumentException(getAlgorithmName() + " requires 128 bit or 256 bit key");
				}

				int tsOff = (keyBytes.Length - 16) / 4;
				engineState[0] = TAU_SIGMA[tsOff];
				engineState[5] = TAU_SIGMA[tsOff + 1];
				engineState[10] = TAU_SIGMA[tsOff + 2];
				engineState[15] = TAU_SIGMA[tsOff + 3];

				// Key
				Pack.littleEndianToInt(keyBytes, 0, engineState, 1, 4);
				Pack.littleEndianToInt(keyBytes, keyBytes.Length - 16, engineState, 11, 4);
			}

			// IV
			Pack.littleEndianToInt(ivBytes, 0, engineState, 6, 2);
		}

		public virtual void generateKeyStream(byte[] output)
		{
			salsaCore(rounds, engineState, x);
			Pack.intToLittleEndian(x, output, 0);
		}

		/// <summary>
		/// Salsa20 function
		/// </summary>
		/// <param name="input">   input data </param>
		public static void salsaCore(int rounds, int[] input, int[] x)
		{
			if (input.Length != 16)
			{
				throw new IllegalArgumentException();
			}
			if (x.Length != 16)
			{
				throw new IllegalArgumentException();
			}
			if (rounds % 2 != 0)
			{
				throw new IllegalArgumentException("Number of rounds must be even");
			}

			int x00 = input[0];
			int x01 = input[1];
			int x02 = input[2];
			int x03 = input[3];
			int x04 = input[4];
			int x05 = input[5];
			int x06 = input[6];
			int x07 = input[7];
			int x08 = input[8];
			int x09 = input[9];
			int x10 = input[10];
			int x11 = input[11];
			int x12 = input[12];
			int x13 = input[13];
			int x14 = input[14];
			int x15 = input[15];

			for (int i = rounds; i > 0; i -= 2)
			{
				x04 ^= rotl(x00 + x12, 7);
				x08 ^= rotl(x04 + x00, 9);
				x12 ^= rotl(x08 + x04, 13);
				x00 ^= rotl(x12 + x08, 18);
				x09 ^= rotl(x05 + x01, 7);
				x13 ^= rotl(x09 + x05, 9);
				x01 ^= rotl(x13 + x09, 13);
				x05 ^= rotl(x01 + x13, 18);
				x14 ^= rotl(x10 + x06, 7);
				x02 ^= rotl(x14 + x10, 9);
				x06 ^= rotl(x02 + x14, 13);
				x10 ^= rotl(x06 + x02, 18);
				x03 ^= rotl(x15 + x11, 7);
				x07 ^= rotl(x03 + x15, 9);
				x11 ^= rotl(x07 + x03, 13);
				x15 ^= rotl(x11 + x07, 18);

				x01 ^= rotl(x00 + x03, 7);
				x02 ^= rotl(x01 + x00, 9);
				x03 ^= rotl(x02 + x01, 13);
				x00 ^= rotl(x03 + x02, 18);
				x06 ^= rotl(x05 + x04, 7);
				x07 ^= rotl(x06 + x05, 9);
				x04 ^= rotl(x07 + x06, 13);
				x05 ^= rotl(x04 + x07, 18);
				x11 ^= rotl(x10 + x09, 7);
				x08 ^= rotl(x11 + x10, 9);
				x09 ^= rotl(x08 + x11, 13);
				x10 ^= rotl(x09 + x08, 18);
				x12 ^= rotl(x15 + x14, 7);
				x13 ^= rotl(x12 + x15, 9);
				x14 ^= rotl(x13 + x12, 13);
				x15 ^= rotl(x14 + x13, 18);
			}

			x[0] = x00 + input[0];
			x[1] = x01 + input[1];
			x[2] = x02 + input[2];
			x[3] = x03 + input[3];
			x[4] = x04 + input[4];
			x[5] = x05 + input[5];
			x[6] = x06 + input[6];
			x[7] = x07 + input[7];
			x[8] = x08 + input[8];
			x[9] = x09 + input[9];
			x[10] = x10 + input[10];
			x[11] = x11 + input[11];
			x[12] = x12 + input[12];
			x[13] = x13 + input[13];
			x[14] = x14 + input[14];
			x[15] = x15 + input[15];
		}

		/// <summary>
		/// Rotate left
		/// </summary>
		/// <param name="x">   value to rotate </param>
		/// <param name="y">   amount to rotate x
		/// </param>
		/// <returns>  rotated x </returns>
		protected internal static int rotl(int x, int y)
		{
			return (x << y) | ((int)((uint)x >> -y));
		}

		private void resetLimitCounter()
		{
			cW0 = 0;
			cW1 = 0;
			cW2 = 0;
		}

		private bool limitExceeded()
		{
			if (++cW0 == 0)
			{
				if (++cW1 == 0)
				{
					return (++cW2 & 0x20) != 0; // 2^(32 + 32 + 6)
				}
			}

			return false;
		}

		/*
		 * this relies on the fact len will always be positive.
		 */
		private bool limitExceeded(int len)
		{
			cW0 += len;
			if (cW0 < len && cW0 >= 0)
			{
				if (++cW1 == 0)
				{
					return (++cW2 & 0x20) != 0; // 2^(32 + 32 + 6)
				}
			}

			return false;
		}
	}

}