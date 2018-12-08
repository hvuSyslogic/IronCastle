﻿using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Pack = org.bouncycastle.util.Pack;

	/// <summary>
	/// Implementation of DSTU7624 XTS mode
	/// </summary>
	public class KXTSBlockCipher : BufferedBlockCipher
	{
		/*
		 * Constants for GF(2^m) operations
		 *
		 * GF(2 ^ 128) -> x^128 + x^7 + x^2 + x + 1
		 * GF(2 ^ 256) -> x^256 + x^10 + x^5 + x^2 + 1
		 * GF(2 ^ 512) -> x^512 + x^8 + x^5 + x^2 + 1
		 */
		private const long RED_POLY_128 = 0x0087L;
		private const long RED_POLY_256 = 0x0425L;
		private const long RED_POLY_512 = 0x0125L;

		protected internal static long getReductionPolynomial(int blockSize)
		{
			switch (blockSize)
			{
			case 16:
				return RED_POLY_128;
			case 32:
				return RED_POLY_256;
			case 64:
				return RED_POLY_512;
			default:
				throw new IllegalArgumentException("Only 128, 256, and 512 -bit block sizes supported");
			}
		}

		private readonly int blockSize;
		private readonly long reductionPolynomial;
		private readonly long[] tw_init, tw_current;
		private int counter;

		public KXTSBlockCipher(BlockCipher cipher)
		{
	//        super(cipher);
			this.cipher = cipher;

			this.blockSize = cipher.getBlockSize();
			this.reductionPolynomial = getReductionPolynomial(blockSize);
			this.tw_init = new long[(int)((uint)blockSize >> 3)];
			this.tw_current = new long[(int)((uint)blockSize >> 3)];
			this.counter = -1;
		}

		public override int getOutputSize(int length)
		{
			return length;
		}

		public override int getUpdateOutputSize(int len)
		{
			return len;
		}

		public override void init(bool forEncryption, CipherParameters parameters)
		{
			if (!(parameters is ParametersWithIV))
			{
				throw new IllegalArgumentException("Invalid parameters passed");
			}

			ParametersWithIV ivParam = (ParametersWithIV)parameters;
			parameters = ivParam.getParameters();

			byte[] iv = ivParam.getIV();

			/*
			 * TODO We need to check what the rule is supposed to be for IVs that aren't exactly one block.
			 * 
			 * Given general little-endianness, presumably a short IV should be right-padded with zeroes.
			 */
			if (iv.Length != blockSize)
			{
				throw new IllegalArgumentException("Currently only support IVs of exactly one block");
			}

			byte[] tweak = new byte[blockSize];
			JavaSystem.arraycopy(iv, 0, tweak, 0, blockSize);

			cipher.init(true, parameters);
			cipher.processBlock(tweak, 0, tweak, 0);

			cipher.init(forEncryption, parameters);
			Pack.littleEndianToLong(tweak, 0, tw_init);
			JavaSystem.arraycopy(tw_init, 0, tw_current, 0, tw_init.Length);
			counter = 0;
		}

		public override int processByte(byte @in, byte[] @out, int outOff)
		{
			/*
			 * TODO This class isn't really behaving like a BufferedBlockCipher yet
			 */
			throw new IllegalStateException("unsupported operation");
		}

		public override int processBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
		{
			if (input.Length - inOff < len)
			{
				throw new DataLengthException("Input buffer too short");
			}
			if (output.Length - inOff < len)
			{
				throw new OutputLengthException("Output buffer too short");
			}
			if (len % blockSize != 0)
			{
				throw new IllegalArgumentException("Partial blocks not supported");
			}

			for (int pos = 0; pos < len; pos += blockSize)
			{
				processBlock(input, inOff + pos, output, outOff + pos);
			}

			return len;
		}

		private void processBlock(byte[] input, int inOff, byte[] output, int outOff)
		{
			/*
			 * A somewhat arbitrary limit of 2^32 - 1 blocks
			 */
			if (counter == -1)
			{
				throw new IllegalStateException("Attempt to process too many blocks");
			}

			++counter;

			/*
			 * Multiply tweak by 'alpha', which is just 2
			 */
			GF_double(reductionPolynomial, tw_current);

			byte[] tweak = new byte[blockSize];
			Pack.longToLittleEndian(tw_current, tweak, 0);

			byte[] buffer = new byte[blockSize];
			JavaSystem.arraycopy(tweak, 0, buffer, 0, blockSize);

			for (int i = 0; i < blockSize; ++i)
			{
				buffer[i] ^= input[inOff + i];
			}

			cipher.processBlock(buffer, 0, buffer, 0);

			for (int i = 0; i < blockSize; ++i)
			{
				output[outOff + i] = (byte)(buffer[i] ^ tweak[i]);
			}
		}

		public override int doFinal(byte[] output, int outOff)
		{
			reset();

			return 0;
		}

		public override void reset()
		{
	//        super.reset();
			cipher.reset();

			JavaSystem.arraycopy(tw_init, 0, tw_current, 0, tw_init.Length);
			counter = 0;
		}

		private static void GF_double(long redPoly, long[] z)
		{
			long c = 0;
			for (int i = 0; i < z.Length; ++i)
			{
				long zVal = z[i];
				long bit = (long)((ulong)zVal >> 63);
				z[i] = (zVal << 1) ^ c;
				c = bit;
			}

			z[0] ^= redPoly & -c;
		}
	}

}