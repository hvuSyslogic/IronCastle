using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
		
	public class VMPCEngine : StreamCipher
	{
		/*
		 * variables to hold the state of the VMPC engine during encryption and
		 * decryption
		 */
		protected internal byte n = 0;
		protected internal byte[] P = null;
		protected internal byte s = 0;

		protected internal byte[] workingIV;
		protected internal byte[] workingKey;

		public virtual string getAlgorithmName()
		{
			return "VMPC";
		}

		/// <summary>
		/// initialise a VMPC cipher.
		/// </summary>
		/// <param name="forEncryption">
		///    whether or not we are for encryption. </param>
		/// <param name="params">
		///    the parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException">
		///    if the params argument is inappropriate. </exception>
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			if (!(@params is ParametersWithIV))
			{
				throw new IllegalArgumentException("VMPC init parameters must include an IV");
			}

			ParametersWithIV ivParams = (ParametersWithIV) @params;

			if (!(ivParams.getParameters() is KeyParameter))
			{
				throw new IllegalArgumentException("VMPC init parameters must include a key");
			}

			KeyParameter key = (KeyParameter) ivParams.getParameters();

			this.workingIV = ivParams.getIV();

			if (workingIV == null || workingIV.Length < 1 || workingIV.Length > 768)
			{
				throw new IllegalArgumentException("VMPC requires 1 to 768 bytes of IV");
			}

			this.workingKey = key.getKey();

			initKey(this.workingKey, this.workingIV);
		}

		public virtual void initKey(byte[] keyBytes, byte[] ivBytes)
		{
			s = 0;
			P = new byte[256];
			for (int i = 0; i < 256; i++)
			{
				P[i] = (byte) i;
			}

			for (int m = 0; m < 768; m++)
			{
				s = P[(s + P[m & 0xff] + keyBytes[m % keyBytes.Length]) & 0xff];
				byte temp = P[m & 0xff];
				P[m & 0xff] = P[s & 0xff];
				P[s & 0xff] = temp;
			}
			for (int m = 0; m < 768; m++)
			{
				s = P[(s + P[m & 0xff] + ivBytes[m % ivBytes.Length]) & 0xff];
				byte temp = P[m & 0xff];
				P[m & 0xff] = P[s & 0xff];
				P[s & 0xff] = temp;
			}
			n = 0;
		}

		public virtual int processBytes(byte[] @in, int inOff, int len, byte[] @out, int outOff)
		{
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
				s = P[(s + P[n & 0xff]) & 0xff];
				byte z = P[(P[(P[s & 0xff]) & 0xff] + 1) & 0xff];
				// encryption
				byte temp = P[n & 0xff];
				P[n & 0xff] = P[s & 0xff];
				P[s & 0xff] = temp;
				n = unchecked((byte)((n + 1) & 0xff));

				// xor
				@out[i + outOff] = (byte)(@in[i + inOff] ^ z);
			}

			return len;
		}

		public virtual void reset()
		{
			initKey(this.workingKey, this.workingIV);
		}

		public virtual byte returnByte(byte @in)
		{
			s = P[(s + P[n & 0xff]) & 0xff];
			byte z = P[(P[(P[s & 0xff]) & 0xff] + 1) & 0xff];
			// encryption
			byte temp = P[n & 0xff];
			P[n & 0xff] = P[s & 0xff];
			P[s & 0xff] = temp;
			n = unchecked((byte)((n + 1) & 0xff));

			// xor
			return (byte)(@in ^ z);
		}
	}

}