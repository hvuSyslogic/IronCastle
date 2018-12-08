using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;

	/// <summary>
	/// Implementation of Martin Hell's, Thomas Johansson's and Willi Meier's stream
	/// cipher, Grain v1.
	/// </summary>
	public class Grainv1Engine : StreamCipher
	{

		/// <summary>
		/// Constants
		/// </summary>
		private const int STATE_SIZE = 5;

		/// <summary>
		/// Variables to hold the state of the engine during encryption and
		/// decryption
		/// </summary>
		private byte[] workingKey;
		private byte[] workingIV;
		private byte[] @out;
		private int[] lfsr;
		private int[] nfsr;
		private int output;
		private int index = 2;

		private bool initialised = false;

		public virtual string getAlgorithmName()
		{
			return "Grain v1";
		}

		/// <summary>
		/// Initialize a Grain v1 cipher.
		/// </summary>
		/// <param name="forEncryption"> Whether or not we are for encryption. </param>
		/// <param name="params">        The parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException"> If the params argument is inappropriate. </exception>
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			/// <summary>
			/// Grain encryption and decryption is completely symmetrical, so the
			/// 'forEncryption' is irrelevant.
			/// </summary>
			if (!(@params is ParametersWithIV))
			{
				throw new IllegalArgumentException("Grain v1 Init parameters must include an IV");
			}

			ParametersWithIV ivParams = (ParametersWithIV)@params;

			byte[] iv = ivParams.getIV();

			if (iv == null || iv.Length != 8)
			{
				throw new IllegalArgumentException("Grain v1 requires exactly 8 bytes of IV");
			}

			if (!(ivParams.getParameters() is KeyParameter))
			{
				throw new IllegalArgumentException("Grain v1 Init parameters must include a key");
			}

			KeyParameter key = (KeyParameter)ivParams.getParameters();

			/// <summary>
			/// Initialize variables.
			/// </summary>
			workingIV = new byte[key.getKey().Length];
			workingKey = new byte[key.getKey().Length];
			lfsr = new int[STATE_SIZE];
			nfsr = new int[STATE_SIZE];
			@out = new byte[2];

			JavaSystem.arraycopy(iv, 0, workingIV, 0, iv.Length);
			JavaSystem.arraycopy(key.getKey(), 0, workingKey, 0, key.getKey().Length);

			reset();
		}

		/// <summary>
		/// 160 clocks initialization phase.
		/// </summary>
		private void initGrain()
		{
			for (int i = 0; i < 10; i++)
			{
				output = getOutput();
				nfsr = shift(nfsr, getOutputNFSR() ^ lfsr[0] ^ output);
				lfsr = shift(lfsr, getOutputLFSR() ^ output);
			}
			initialised = true;
		}

		/// <summary>
		/// Get output from non-linear function g(x).
		/// </summary>
		/// <returns> Output from NFSR. </returns>
		private int getOutputNFSR()
		{
			int b0 = nfsr[0];
			int b9 = (int)((uint)nfsr[0] >> 9) | nfsr[1] << 7;
			int b14 = (int)((uint)nfsr[0] >> 14) | nfsr[1] << 2;
			int b15 = (int)((uint)nfsr[0] >> 15) | nfsr[1] << 1;
			int b21 = (int)((uint)nfsr[1] >> 5) | nfsr[2] << 11;
			int b28 = (int)((uint)nfsr[1] >> 12) | nfsr[2] << 4;
			int b33 = (int)((uint)nfsr[2] >> 1) | nfsr[3] << 15;
			int b37 = (int)((uint)nfsr[2] >> 5) | nfsr[3] << 11;
			int b45 = (int)((uint)nfsr[2] >> 13) | nfsr[3] << 3;
			int b52 = (int)((uint)nfsr[3] >> 4) | nfsr[4] << 12;
			int b60 = (int)((uint)nfsr[3] >> 12) | nfsr[4] << 4;
			int b62 = (int)((uint)nfsr[3] >> 14) | nfsr[4] << 2;
			int b63 = (int)((uint)nfsr[3] >> 15) | nfsr[4] << 1;

			return (b62 ^ b60 ^ b52 ^ b45 ^ b37 ^ b33 ^ b28 ^ b21 ^ b14 ^ b9 ^ b0 ^ b63 & b60 ^ b37 & b33 ^ b15 & b9 ^ b60 & b52 & b45 ^ b33 & b28 & b21 ^ b63 & b45 & b28 & b9 ^ b60 & b52 & b37 & b33 ^ b63 & b60 & b21 & b15 ^ b63 & b60 & b52 & b45 & b37 ^ b33 & b28 & b21 & b15 & b9 ^ b52 & b45 & b37 & b33 & b28 & b21) & 0x0000FFFF;
		}

		/// <summary>
		/// Get output from linear function f(x).
		/// </summary>
		/// <returns> Output from LFSR. </returns>
		private int getOutputLFSR()
		{
			int s0 = lfsr[0];
			int s13 = (int)((uint)lfsr[0] >> 13) | lfsr[1] << 3;
			int s23 = (int)((uint)lfsr[1] >> 7) | lfsr[2] << 9;
			int s38 = (int)((uint)lfsr[2] >> 6) | lfsr[3] << 10;
			int s51 = (int)((uint)lfsr[3] >> 3) | lfsr[4] << 13;
			int s62 = (int)((uint)lfsr[3] >> 14) | lfsr[4] << 2;

			return (s0 ^ s13 ^ s23 ^ s38 ^ s51 ^ s62) & 0x0000FFFF;
		}

		/// <summary>
		/// Get output from output function h(x).
		/// </summary>
		/// <returns> Output from h(x). </returns>
		private int getOutput()
		{
			int b1 = (int)((uint)nfsr[0] >> 1) | nfsr[1] << 15;
			int b2 = (int)((uint)nfsr[0] >> 2) | nfsr[1] << 14;
			int b4 = (int)((uint)nfsr[0] >> 4) | nfsr[1] << 12;
			int b10 = (int)((uint)nfsr[0] >> 10) | nfsr[1] << 6;
			int b31 = (int)((uint)nfsr[1] >> 15) | nfsr[2] << 1;
			int b43 = (int)((uint)nfsr[2] >> 11) | nfsr[3] << 5;
			int b56 = (int)((uint)nfsr[3] >> 8) | nfsr[4] << 8;
			int b63 = (int)((uint)nfsr[3] >> 15) | nfsr[4] << 1;
			int s3 = (int)((uint)lfsr[0] >> 3) | lfsr[1] << 13;
			int s25 = (int)((uint)lfsr[1] >> 9) | lfsr[2] << 7;
			int s46 = (int)((uint)lfsr[2] >> 14) | lfsr[3] << 2;
			int s64 = lfsr[4];

			return (s25 ^ b63 ^ s3 & s64 ^ s46 & s64 ^ s64 & b63 ^ s3 & s25 & s46 ^ s3 & s46 & s64 ^ s3 & s46 & b63 ^ s25 & s46 & b63 ^ s46 & s64 & b63 ^ b1 ^ b2 ^ b4 ^ b10 ^ b31 ^ b43 ^ b56) & 0x0000FFFF;
		}

		/// <summary>
		/// Shift array 16 bits and add val to index.length - 1.
		/// </summary>
		/// <param name="array"> The array to shift. </param>
		/// <param name="val">   The value to shift in. </param>
		/// <returns> The shifted array with val added to index.length - 1. </returns>
		private int[] shift(int[] array, int val)
		{
			array[0] = array[1];
			array[1] = array[2];
			array[2] = array[3];
			array[3] = array[4];
			array[4] = val;

			return array;
		}

		/// <summary>
		/// Set keys, reset cipher.
		/// </summary>
		/// <param name="keyBytes"> The key. </param>
		/// <param name="ivBytes">  The IV. </param>
		private void setKey(byte[] keyBytes, byte[] ivBytes)
		{
			ivBytes[8] = unchecked((byte)0xFF);
			ivBytes[9] = unchecked((byte)0xFF);
			workingKey = keyBytes;
			workingIV = ivBytes;

			/// <summary>
			/// Load NFSR and LFSR
			/// </summary>
			int j = 0;
			for (int i = 0; i < nfsr.Length; i++)
			{
				nfsr[i] = (workingKey[j + 1] << 8 | workingKey[j] & 0xFF) & 0x0000FFFF;
				lfsr[i] = (workingIV[j + 1] << 8 | workingIV[j] & 0xFF) & 0x0000FFFF;
				j += 2;
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

			for (int i = 0; i < len; i++)
			{
				@out[outOff + i] = (byte)(@in[inOff + i] ^ getKeyStream());
			}

			return len;
		}

		public virtual void reset()
		{
			index = 2;
			setKey(workingKey, workingIV);
			initGrain();
		}

		/// <summary>
		/// Run Grain one round(i.e. 16 bits).
		/// </summary>
		private void oneRound()
		{
			output = getOutput();
			@out[0] = (byte)output;
			@out[1] = (byte)(output >> 8);

			nfsr = shift(nfsr, getOutputNFSR() ^ lfsr[0]);
			lfsr = shift(lfsr, getOutputLFSR());
		}

		public virtual byte returnByte(byte @in)
		{
			if (!initialised)
			{
				throw new IllegalStateException(getAlgorithmName() + " not initialised");
			}
			return (byte)(@in ^ getKeyStream());
		}

		private byte getKeyStream()
		{
			if (index > 1)
			{
				oneRound();
				index = 0;
			}
			return @out[index++];
		}
	}
}