using org.bouncycastle.crypto.engines;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.macs
{
			
	/// <summary>
	/// Implementation of DSTU7624 MAC mode
	/// </summary>
	public class DSTU7624Mac : Mac
	{
		private const int BITS_IN_BYTE = 8;

		private byte[] buf;
		private int bufOff;

		private int macSize;
		private int blockSize;
		private DSTU7624Engine engine;

		private byte[] c, cTemp, kDelta;

		public DSTU7624Mac(int blockBitLength, int q)
		{
			this.engine = new DSTU7624Engine(blockBitLength);
			this.blockSize = blockBitLength / BITS_IN_BYTE;
			this.macSize = q / BITS_IN_BYTE;
			this.c = new byte[blockSize];
			this.kDelta = new byte[blockSize];
			this.cTemp = new byte[blockSize];
			this.buf = new byte[blockSize];
		}

		public virtual void init(CipherParameters @params)
		{
			if (@params is KeyParameter)
			{
				engine.init(true, @params);
				engine.processBlock(kDelta, 0, kDelta, 0);
			}
			else
			{
				throw new IllegalArgumentException("Invalid parameter passed to DSTU7624Mac");
			}
		}

		public virtual string getAlgorithmName()
		{
			return "DSTU7624Mac";
		}

		public virtual int getMacSize()
		{
			return macSize;
		}

		public virtual void update(byte @in)
		{
			if (bufOff == buf.Length)
			{
				processBlock(buf, 0);
				bufOff = 0;
			}

			buf[bufOff++] = @in;
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			if (len < 0)
			{
				throw new IllegalArgumentException("can't have a negative input length!");
			}

			int blockSize = engine.getBlockSize();
			int gapLen = blockSize - bufOff;

			if (len > gapLen)
			{
				JavaSystem.arraycopy(@in, inOff, buf, bufOff, gapLen);

				processBlock(buf, 0);

				bufOff = 0;
				len -= gapLen;
				inOff += gapLen;

				while (len > blockSize)
				{
					processBlock(@in, inOff);

					len -= blockSize;
					inOff += blockSize;
				}
			}

			JavaSystem.arraycopy(@in, inOff, buf, bufOff, len);

			bufOff += len;
		}

		private void processBlock(byte[] @in, int inOff)
		{
			xor(c, 0, @in, inOff, cTemp);

			engine.processBlock(cTemp, 0, c, 0);
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			if (bufOff % buf.Length != 0)
			{
				throw new DataLengthException("input must be a multiple of blocksize");
			}

			//Last block
			xor(c, 0, buf, 0, cTemp);
			xor(cTemp, 0, kDelta, 0, c);
			engine.processBlock(c, 0, c, 0);

			if (macSize + outOff > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			JavaSystem.arraycopy(c, 0, @out, outOff, macSize);

			return macSize;
		}

		public virtual void reset()
		{
			Arrays.fill(c, 0x00);
			Arrays.fill(cTemp, 0x00);
			Arrays.fill(kDelta, 0x00);
			Arrays.fill(buf, 0x00);
			engine.reset();
			engine.processBlock(kDelta, 0, kDelta, 0);
			bufOff = 0;
		}

		private void xor(byte[] x, int xOff, byte[] y, int yOff, byte[] x_xor_y)
		{

			if (x.Length - xOff < blockSize || y.Length - yOff < blockSize || x_xor_y.Length < blockSize)
			{
				throw new IllegalArgumentException("some of input buffers too short");
			}
			for (int byteIndex = 0; byteIndex < blockSize; byteIndex++)
			{
				x_xor_y[byteIndex] = (byte)(x[byteIndex + xOff] ^ y[byteIndex + yOff]);
			}
		}

	}

}