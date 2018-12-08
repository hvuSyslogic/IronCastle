using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;

	/// <summary>
	/// Implementation of Martin Hell's, Thomas Johansson's and Willi Meier's stream
	/// cipher, Grain-128.
	/// </summary>
	public class Grain128Engine : StreamCipher
	{

		/// <summary>
		/// Constants
		/// </summary>
		private const int STATE_SIZE = 4;

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
		private int index = 4;

		private bool initialised = false;

		public virtual string getAlgorithmName()
		{
			return "Grain-128";
		}

		/// <summary>
		/// Initialize a Grain-128 cipher.
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
				throw new IllegalArgumentException("Grain-128 Init parameters must include an IV");
			}

			ParametersWithIV ivParams = (ParametersWithIV)@params;

			byte[] iv = ivParams.getIV();

			if (iv == null || iv.Length != 12)
			{
				throw new IllegalArgumentException("Grain-128  requires exactly 12 bytes of IV");
			}

			if (!(ivParams.getParameters() is KeyParameter))
			{
				throw new IllegalArgumentException("Grain-128 Init parameters must include a key");
			}

			KeyParameter key = (KeyParameter)ivParams.getParameters();

			/// <summary>
			/// Initialize variables.
			/// </summary>
			workingIV = new byte[key.getKey().Length];
			workingKey = new byte[key.getKey().Length];
			lfsr = new int[STATE_SIZE];
			nfsr = new int[STATE_SIZE];
			@out = new byte[4];

			JavaSystem.arraycopy(iv, 0, workingIV, 0, iv.Length);
			JavaSystem.arraycopy(key.getKey(), 0, workingKey, 0, key.getKey().Length);

			reset();
		}

		/// <summary>
		/// 256 clocks initialization phase.
		/// </summary>
		private void initGrain()
		{
			for (int i = 0; i < 8; i++)
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
			int b3 = (int)((uint)nfsr[0] >> 3) | nfsr[1] << 29;
			int b11 = (int)((uint)nfsr[0] >> 11) | nfsr[1] << 21;
			int b13 = (int)((uint)nfsr[0] >> 13) | nfsr[1] << 19;
			int b17 = (int)((uint)nfsr[0] >> 17) | nfsr[1] << 15;
			int b18 = (int)((uint)nfsr[0] >> 18) | nfsr[1] << 14;
			int b26 = (int)((uint)nfsr[0] >> 26) | nfsr[1] << 6;
			int b27 = (int)((uint)nfsr[0] >> 27) | nfsr[1] << 5;
			int b40 = (int)((uint)nfsr[1] >> 8) | nfsr[2] << 24;
			int b48 = (int)((uint)nfsr[1] >> 16) | nfsr[2] << 16;
			int b56 = (int)((uint)nfsr[1] >> 24) | nfsr[2] << 8;
			int b59 = (int)((uint)nfsr[1] >> 27) | nfsr[2] << 5;
			int b61 = (int)((uint)nfsr[1] >> 29) | nfsr[2] << 3;
			int b65 = (int)((uint)nfsr[2] >> 1) | nfsr[3] << 31;
			int b67 = (int)((uint)nfsr[2] >> 3) | nfsr[3] << 29;
			int b68 = (int)((uint)nfsr[2] >> 4) | nfsr[3] << 28;
			int b84 = (int)((uint)nfsr[2] >> 20) | nfsr[3] << 12;
			int b91 = (int)((uint)nfsr[2] >> 27) | nfsr[3] << 5;
			int b96 = nfsr[3];

			return b0 ^ b26 ^ b56 ^ b91 ^ b96 ^ b3 & b67 ^ b11 & b13 ^ b17 & b18 ^ b27 & b59 ^ b40 & b48 ^ b61 & b65 ^ b68 & b84;
		}

		/// <summary>
		/// Get output from linear function f(x).
		/// </summary>
		/// <returns> Output from LFSR. </returns>
		private int getOutputLFSR()
		{
			int s0 = lfsr[0];
			int s7 = (int)((uint)lfsr[0] >> 7) | lfsr[1] << 25;
			int s38 = (int)((uint)lfsr[1] >> 6) | lfsr[2] << 26;
			int s70 = (int)((uint)lfsr[2] >> 6) | lfsr[3] << 26;
			int s81 = (int)((uint)lfsr[2] >> 17) | lfsr[3] << 15;
			int s96 = lfsr[3];

			return s0 ^ s7 ^ s38 ^ s70 ^ s81 ^ s96;
		}

		/// <summary>
		/// Get output from output function h(x).
		/// </summary>
		/// <returns> Output from h(x). </returns>
		private int getOutput()
		{
			int b2 = (int)((uint)nfsr[0] >> 2) | nfsr[1] << 30;
			int b12 = (int)((uint)nfsr[0] >> 12) | nfsr[1] << 20;
			int b15 = (int)((uint)nfsr[0] >> 15) | nfsr[1] << 17;
			int b36 = (int)((uint)nfsr[1] >> 4) | nfsr[2] << 28;
			int b45 = (int)((uint)nfsr[1] >> 13) | nfsr[2] << 19;
			int b64 = nfsr[2];
			int b73 = (int)((uint)nfsr[2] >> 9) | nfsr[3] << 23;
			int b89 = (int)((uint)nfsr[2] >> 25) | nfsr[3] << 7;
			int b95 = (int)((uint)nfsr[2] >> 31) | nfsr[3] << 1;
			int s8 = (int)((uint)lfsr[0] >> 8) | lfsr[1] << 24;
			int s13 = (int)((uint)lfsr[0] >> 13) | lfsr[1] << 19;
			int s20 = (int)((uint)lfsr[0] >> 20) | lfsr[1] << 12;
			int s42 = (int)((uint)lfsr[1] >> 10) | lfsr[2] << 22;
			int s60 = (int)((uint)lfsr[1] >> 28) | lfsr[2] << 4;
			int s79 = (int)((uint)lfsr[2] >> 15) | lfsr[3] << 17;
			int s93 = (int)((uint)lfsr[2] >> 29) | lfsr[3] << 3;
			int s95 = (int)((uint)lfsr[2] >> 31) | lfsr[3] << 1;

			return b12 & s8 ^ s13 & s20 ^ b95 & s42 ^ s60 & s79 ^ b12 & b95 & s95 ^ s93 ^ b2 ^ b15 ^ b36 ^ b45 ^ b64 ^ b73 ^ b89;
		}

		/// <summary>
		/// Shift array 32 bits and add val to index.length - 1.
		/// </summary>
		/// <param name="array"> The array to shift. </param>
		/// <param name="val">   The value to shift in. </param>
		/// <returns> The shifted array with val added to index.length - 1. </returns>
		private int[] shift(int[] array, int val)
		{
			array[0] = array[1];
			array[1] = array[2];
			array[2] = array[3];
			array[3] = val;

			return array;
		}

		/// <summary>
		/// Set keys, reset cipher.
		/// </summary>
		/// <param name="keyBytes"> The key. </param>
		/// <param name="ivBytes">  The IV. </param>
		private void setKey(byte[] keyBytes, byte[] ivBytes)
		{
			ivBytes[12] = unchecked((byte)0xFF);
			ivBytes[13] = unchecked((byte)0xFF);
			ivBytes[14] = unchecked((byte)0xFF);
			ivBytes[15] = unchecked((byte)0xFF);
			workingKey = keyBytes;
			workingIV = ivBytes;

			/// <summary>
			/// Load NFSR and LFSR
			/// </summary>
			int j = 0;
			for (int i = 0; i < nfsr.Length; i++)
			{
				nfsr[i] = ((workingKey[j + 3]) << 24) | ((workingKey[j + 2]) << 16) & 0x00FF0000 | ((workingKey[j + 1]) << 8) & 0x0000FF00 | ((workingKey[j]) & 0x000000FF);

				lfsr[i] = ((workingIV[j + 3]) << 24) | ((workingIV[j + 2]) << 16) & 0x00FF0000 | ((workingIV[j + 1]) << 8) & 0x0000FF00 | ((workingIV[j]) & 0x000000FF);
				j += 4;
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
			index = 4;
			setKey(workingKey, workingIV);
			initGrain();
		}

		/// <summary>
		/// Run Grain one round(i.e. 32 bits).
		/// </summary>
		private void oneRound()
		{
			output = getOutput();
			@out[0] = (byte)output;
			@out[1] = (byte)(output >> 8);
			@out[2] = (byte)(output >> 16);
			@out[3] = (byte)(output >> 24);

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
			if (index > 3)
			{
				oneRound();
				index = 0;
			}
			return @out[index++];
		}
	}

}