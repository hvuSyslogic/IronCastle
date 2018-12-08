﻿using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.macs
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;

	public class VMPCMac : Mac
	{
		private byte g;

		private byte n = 0;
		private byte[] P = null;
		private byte s = 0;

		private byte[] T;
		private byte[] workingIV;

		private byte[] workingKey;

		private byte x1, x2, x3, x4;

		public virtual int doFinal(byte[] @out, int outOff)
		{
			// Execute the Post-Processing Phase
			for (int r = 1; r < 25; r++)
			{
				s = P[(s + P[n & 0xff]) & 0xff];

				x4 = P[(x4 + x3 + r) & 0xff];
				x3 = P[(x3 + x2 + r) & 0xff];
				x2 = P[(x2 + x1 + r) & 0xff];
				x1 = P[(x1 + s + r) & 0xff];
				T[g & 0x1f] = (byte)(T[g & 0x1f] ^ x1);
				T[(g + 1) & 0x1f] = (byte)(T[(g + 1) & 0x1f] ^ x2);
				T[(g + 2) & 0x1f] = (byte)(T[(g + 2) & 0x1f] ^ x3);
				T[(g + 3) & 0x1f] = (byte)(T[(g + 3) & 0x1f] ^ x4);
				g = (byte)((g + 4) & 0x1f);

				byte temp = P[n & 0xff];
				P[n & 0xff] = P[s & 0xff];
				P[s & 0xff] = temp;
				n = unchecked((byte)((n + 1) & 0xff));
			}

			// Input T to the IV-phase of the VMPC KSA
			for (int m = 0; m < 768; m++)
			{
				s = P[(s + P[m & 0xff] + T[m & 0x1f]) & 0xff];
				byte temp = P[m & 0xff];
				P[m & 0xff] = P[s & 0xff];
				P[s & 0xff] = temp;
			}

			// Store 20 new outputs of the VMPC Stream Cipher in table M
			byte[] M = new byte[20];
			for (int i = 0; i < 20; i++)
			{
				s = P[(s + P[i & 0xff]) & 0xff];
				M[i] = P[(P[(P[s & 0xff]) & 0xff] + 1) & 0xff];

				byte temp = P[i & 0xff];
				P[i & 0xff] = P[s & 0xff];
				P[s & 0xff] = temp;
			}

			JavaSystem.arraycopy(M, 0, @out, outOff, M.Length);
			reset();

			return M.Length;
		}

		public virtual string getAlgorithmName()
		{
			return "VMPC-MAC";
		}

		public virtual int getMacSize()
		{
			return 20;
		}

		public virtual void init(CipherParameters @params)
		{
			if (!(@params is ParametersWithIV))
			{
				throw new IllegalArgumentException("VMPC-MAC Init parameters must include an IV");
			}

			ParametersWithIV ivParams = (ParametersWithIV) @params;
			KeyParameter key = (KeyParameter) ivParams.getParameters();

			if (!(ivParams.getParameters() is KeyParameter))
			{
				throw new IllegalArgumentException("VMPC-MAC Init parameters must include a key");
			}

			this.workingIV = ivParams.getIV();

			if (workingIV == null || workingIV.Length < 1 || workingIV.Length > 768)
			{
				throw new IllegalArgumentException("VMPC-MAC requires 1 to 768 bytes of IV");
			}

			this.workingKey = key.getKey();

			reset();

		}

		private void initKey(byte[] keyBytes, byte[] ivBytes)
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

		public virtual void reset()
		{
			initKey(this.workingKey, this.workingIV);
			g = x1 = x2 = x3 = x4 = n = 0;
			T = new byte[32];
			for (int i = 0; i < 32; i++)
			{
				T[i] = 0;
			}
		}

		public virtual void update(byte @in)
		{
			s = P[(s + P[n & 0xff]) & 0xff];
			byte c = (byte)(@in ^ P[(P[(P[s & 0xff]) & 0xff] + 1) & 0xff]);

			x4 = P[(x4 + x3) & 0xff];
			x3 = P[(x3 + x2) & 0xff];
			x2 = P[(x2 + x1) & 0xff];
			x1 = P[(x1 + s + c) & 0xff];
			T[g & 0x1f] = (byte)(T[g & 0x1f] ^ x1);
			T[(g + 1) & 0x1f] = (byte)(T[(g + 1) & 0x1f] ^ x2);
			T[(g + 2) & 0x1f] = (byte)(T[(g + 2) & 0x1f] ^ x3);
			T[(g + 3) & 0x1f] = (byte)(T[(g + 3) & 0x1f] ^ x4);
			g = (byte)((g + 4) & 0x1f);

			byte temp = P[n & 0xff];
			P[n & 0xff] = P[s & 0xff];
			P[s & 0xff] = temp;
			n = unchecked((byte)((n + 1) & 0xff));
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			if ((inOff + len) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			for (int i = 0; i < len; i++)
			{
				update(@in[inOff + i]);
			}
		}
	}

}