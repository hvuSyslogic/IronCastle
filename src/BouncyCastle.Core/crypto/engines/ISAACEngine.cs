using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.engines
{
		
	/// <summary>
	/// Implementation of Bob Jenkin's ISAAC (Indirection Shift Accumulate Add and Count).
	/// see: http://www.burtleburtle.net/bob/rand/isaacafa.html
	/// </summary>
	public class ISAACEngine : StreamCipher
	{
		private bool InstanceFieldsInitialized = false;

		public ISAACEngine()
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
		}

		private void InitializeInstanceFields()
		{
			stateArraySize = sizeL << 5;
			keyStream = new byte[stateArraySize << 2];
		}

		// Constants
		private int sizeL = 8, stateArraySize; // 256

		// Cipher's internal state
		private int[] engineState = null, results = null; // randrsl
		private int a = 0, b = 0, c = 0;

		// Engine state
		private int index = 0;
		private byte[] keyStream, workingKey = null;
		private bool initialised = false;

		/// <summary>
		/// initialise an ISAAC cipher.
		/// </summary>
		/// <param name="forEncryption"> whether or not we are for encryption. </param>
		/// <param name="params"> the parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			if (!(@params is KeyParameter))
			{
				throw new IllegalArgumentException("invalid parameter passed to ISAAC init - " + @params.GetType().getName());
			}
			/* 
			 * ISAAC encryption and decryption is completely
			 * symmetrical, so the 'forEncryption' is 
			 * irrelevant.
			 */
			KeyParameter p = (KeyParameter)@params;
			setKey(p.getKey());

			return;
		}

		public virtual byte returnByte(byte @in)
		{
			if (index == 0)
			{
				isaac();
				keyStream = Pack.intToBigEndian(results);
			}
			byte @out = (byte)(keyStream[index] ^ @in);
			index = (index + 1) & 1023;

			return @out;
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

			for (int i = 0; i < len; i++)
			{
				if (index == 0)
				{
					isaac();
					keyStream = Pack.intToBigEndian(results);
				}
				@out[i + outOff] = (byte)(keyStream[index] ^ @in[i + inOff]);
				index = (index + 1) & 1023;
			}

			return len;
		}

		public virtual string getAlgorithmName()
		{
			return "ISAAC";
		}

		public virtual void reset()
		{
			setKey(workingKey);
		}

		// Private implementation
		private void setKey(byte[] keyBytes)
		{
			workingKey = keyBytes;

			if (engineState == null)
			{
				engineState = new int[stateArraySize];
			}

			if (results == null)
			{
				results = new int[stateArraySize];
			}

			int i, j, k;

			// Reset state
			for (i = 0; i < stateArraySize; i++)
			{
				engineState[i] = results[i] = 0;
			}
			a = b = c = 0;

			// Reset index counter for output
			index = 0;

			// Convert the key bytes to ints and put them into results[] for initialization
			byte[] t = new byte[keyBytes.Length + (keyBytes.Length & 3)];
			JavaSystem.arraycopy(keyBytes, 0, t, 0, keyBytes.Length);
			for (i = 0; i < t.Length; i += 4)
			{
				results[(int)((uint)i >> 2)] = Pack.littleEndianToInt(t, i);
			}

			// It has begun?
			int[] abcdefgh = new int[sizeL];

			for (i = 0; i < sizeL; i++)
			{
				abcdefgh[i] = unchecked((int)0x9e3779b9); // Phi (golden ratio)
			}

			for (i = 0; i < 4; i++)
			{
				mix(abcdefgh);
			}

			for (i = 0; i < 2; i++)
			{
				for (j = 0; j < stateArraySize; j += sizeL)
				{
					for (k = 0; k < sizeL; k++)
					{
						abcdefgh[k] += (i < 1) ? results[j + k] : engineState[j + k];
					}

					mix(abcdefgh);

					for (k = 0; k < sizeL; k++)
					{
						engineState[j + k] = abcdefgh[k];
					}
				}
			}

			isaac();

			initialised = true;
		}

		private void isaac()
		{
			int i, x, y;

			b += ++c;
			for (i = 0; i < stateArraySize; i++)
			{
				x = engineState[i];
				switch (i & 3)
				{
					case 0:
						a ^= (a << 13);
						break;
					case 1:
						a ^= ((int)((uint)a >> 6));
						break;
					case 2:
						a ^= (a << 2);
						break;
					case 3:
						a ^= ((int)((uint)a >> 16));
						break;
				}
				a += engineState[(i + 128) & 0xFF];
				engineState[i] = y = engineState[((int)((uint)x >> 2)) & 0xFF] + a + b;
				results[i] = b = engineState[((int)((uint)y >> 10)) & 0xFF] + x;
			}
		}

		private void mix(int[] x)
		{
			x[0] ^= x[1] << 11;
			x[3] += x[0];
			x[1] += x[2];
			x[1] ^= (int)((uint)x[2] >> 2);
			x[4] += x[1];
			x[2] += x[3];
			x[2] ^= x[3] << 8;
			x[5] += x[2];
			x[3] += x[4];
			x[3] ^= (int)((uint)x[4] >> 16);
			x[6] += x[3];
			x[4] += x[5];
			x[4] ^= x[5] << 10;
			x[7] += x[4];
			x[5] += x[6];
			x[5] ^= (int)((uint)x[6] >> 4);
			x[0] += x[5];
			x[6] += x[7];
			x[6] ^= x[7] << 8;
			x[1] += x[6];
			x[7] += x[0];
			x[7] ^= (int)((uint)x[0] >> 9);
			x[2] += x[7];
			x[0] += x[1];
		}
	}

}