using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.macs
{
			
	/// <summary>
	/// implementation of GOST 28147-89 MAC
	/// </summary>
	public class GOST28147Mac : Mac
	{
		private int blockSize = 8;
		private int macSize = 4;
		private int bufOff;
		private byte[] buf;
		private byte[] mac;
		private bool firstStep = true;
		private int[] workingKey = null;
		private byte[] macIV = null;

		//
		// This is default S-box - E_A.
		private byte[] S = new byte[] {0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5, 0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1, 0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9, 0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6, 0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6, 0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6, 0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE, 0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4};

		public GOST28147Mac()
		{
			mac = new byte[blockSize];

			buf = new byte[blockSize];
			bufOff = 0;
		}

		private int[] generateWorkingKey(byte[] userKey)
		{
			if (userKey.Length != 32)
			{
				throw new IllegalArgumentException("Key length invalid. Key needs to be 32 byte - 256 bit!!!");
			}

			int[] key = new int[8];
			for (int i = 0; i != 8; i++)
			{
				key[i] = bytesToint(userKey,i * 4);
			}

			return key;
		}

		public virtual void init(CipherParameters @params)
		{
			reset();
			buf = new byte[blockSize];
			macIV = null;
			if (@params is ParametersWithSBox)
			{
				ParametersWithSBox param = (ParametersWithSBox)@params;

				//
				// Set the S-Box
				//
				JavaSystem.arraycopy(param.getSBox(), 0, this.S, 0, param.getSBox().Length);

				//
				// set key if there is one
				//
				if (param.getParameters() != null)
				{
					workingKey = generateWorkingKey(((KeyParameter)param.getParameters()).getKey());
				}
			}
			else if (@params is KeyParameter)
			{
				workingKey = generateWorkingKey(((KeyParameter)@params).getKey());
			}
			else if (@params is ParametersWithIV)
			{
				ParametersWithIV p = (ParametersWithIV)@params;

				workingKey = generateWorkingKey(((KeyParameter)p.getParameters()).getKey());
				JavaSystem.arraycopy(p.getIV(), 0, mac, 0, mac.Length);
				macIV = p.getIV(); // don't skip the initial CM5Func
			}
			else
			{
			   throw new IllegalArgumentException("invalid parameter passed to GOST28147 init - " + @params.GetType().getName());
			}
		}

		public virtual string getAlgorithmName()
		{
			return "GOST28147Mac";
		}

		public virtual int getMacSize()
		{
			return macSize;
		}

		private int gost28147_mainStep(int n1, int key)
		{
			int cm = (key + n1); // CM1

			// S-box replacing

			int om = S[0 + ((cm >> (0 * 4)) & 0xF)] << (0 * 4);
			om += S[16 + ((cm >> (1 * 4)) & 0xF)] << (1 * 4);
			om += S[32 + ((cm >> (2 * 4)) & 0xF)] << (2 * 4);
			om += S[48 + ((cm >> (3 * 4)) & 0xF)] << (3 * 4);
			om += S[64 + ((cm >> (4 * 4)) & 0xF)] << (4 * 4);
			om += S[80 + ((cm >> (5 * 4)) & 0xF)] << (5 * 4);
			om += S[96 + ((cm >> (6 * 4)) & 0xF)] << (6 * 4);
			om += S[112 + ((cm >> (7 * 4)) & 0xF)] << (7 * 4);

			return om << 11 | (int)((uint)om >> (32 - 11)); // 11-leftshift
		}

		private void gost28147MacFunc(int[] workingKey, byte[] @in, int inOff, byte[] @out, int outOff)
		{
			int N1, N2, tmp; //tmp -> for saving N1
			N1 = bytesToint(@in, inOff);
			N2 = bytesToint(@in, inOff + 4);

			for (int k = 0; k < 2; k++) // 1-16 steps
			{
				for (int j = 0; j < 8; j++)
				{
					tmp = N1;
					N1 = N2 ^ gost28147_mainStep(N1, workingKey[j]); // CM2
					N2 = tmp;
				}
			}

			intTobytes(N1, @out, outOff);
			intTobytes(N2, @out, outOff + 4);
		}

		//array of bytes to type int
		private int bytesToint(byte[] @in, int inOff)
		{
			return ((@in[inOff + 3] << 24) & unchecked((int)0xff000000)) + ((@in[inOff + 2] << 16) & 0xff0000) + ((@in[inOff + 1] << 8) & 0xff00) + (@in[inOff] & 0xff);
		}

		//int to array of bytes
		private void intTobytes(int num, byte[] @out, int outOff)
		{
			@out[outOff + 3] = (byte)((int)((uint)num >> 24));
			@out[outOff + 2] = (byte)((int)((uint)num >> 16));
			@out[outOff + 1] = (byte)((int)((uint)num >> 8));
			@out[outOff] = (byte)num;
		}

		private byte[] CM5func(byte[] buf, int bufOff, byte[] mac)
		{
			byte[] sum = new byte[buf.Length - bufOff];

			JavaSystem.arraycopy(buf, bufOff, sum, 0, mac.Length);

			for (int i = 0; i != mac.Length; i++)
			{
				sum[i] = (byte)(sum[i] ^ mac[i]);
			}

			return sum;
		}

		public virtual void update(byte @in)
		{
			if (bufOff == buf.Length)
			{
				byte[] sumbuf = new byte[buf.Length];
				JavaSystem.arraycopy(buf, 0, sumbuf, 0, mac.Length);

				if (firstStep)
				{
					firstStep = false;
					if (macIV != null)
					{
						sumbuf = CM5func(buf, 0, macIV);
					}
				}
				else
				{
					sumbuf = CM5func(buf, 0, mac);
				}

				gost28147MacFunc(workingKey, sumbuf, 0, mac, 0);
				bufOff = 0;
			}

			buf[bufOff++] = @in;
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
				if (len < 0)
				{
					throw new IllegalArgumentException("Can't have a negative input length!");
				}

				int gapLen = blockSize - bufOff;

				if (len > gapLen)
				{
					JavaSystem.arraycopy(@in, inOff, buf, bufOff, gapLen);

					byte[] sumbuf = new byte[buf.Length];
					JavaSystem.arraycopy(buf, 0, sumbuf, 0, mac.Length);

					if (firstStep)
					{
						firstStep = false;
						if (macIV != null)
						{
							sumbuf = CM5func(buf, 0, macIV);
						}
					}
					else
					{
						sumbuf = CM5func(buf, 0, mac);
					}

					gost28147MacFunc(workingKey, sumbuf, 0, mac, 0);

					bufOff = 0;
					len -= gapLen;
					inOff += gapLen;

					while (len > blockSize)
					{
						sumbuf = CM5func(@in, inOff, mac);
						gost28147MacFunc(workingKey, sumbuf, 0, mac, 0);

						len -= blockSize;
						inOff += blockSize;
					}
				}

				JavaSystem.arraycopy(@in, inOff, buf, bufOff, len);

				bufOff += len;
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			//padding with zero
			while (bufOff < blockSize)
			{
				buf[bufOff] = 0;
				bufOff++;
			}

			byte[] sumbuf = new byte[buf.Length];
			JavaSystem.arraycopy(buf, 0, sumbuf, 0, mac.Length);

			if (firstStep)
			{
				firstStep = false;
			}
			else
			{
				sumbuf = CM5func(buf, 0, mac);
			}

			gost28147MacFunc(workingKey, sumbuf, 0, mac, 0);

			JavaSystem.arraycopy(mac, (mac.Length / 2) - macSize, @out, outOff, macSize);

			reset();

			return macSize;
		}

		public virtual void reset()
		{
			/*
			 * clean the buffer.
			 */
			for (int i = 0; i < buf.Length; i++)
			{
				buf[i] = 0;
			}

			bufOff = 0;

			firstStep = true;
		}
	}

}