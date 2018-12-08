using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.digests
{

	/// <summary>
	/// implementation of SHA-3 based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
	/// <para>
	/// Following the naming conventions used in the C source code to enable easy review of the implementation.
	/// </para>
	/// </summary>
	public class SHA3Digest : KeccakDigest
	{
		private static int checkBitLength(int bitLength)
		{
			switch (bitLength)
			{
			case 224:
			case 256:
			case 384:
			case 512:
				return bitLength;
			default:
				throw new IllegalArgumentException("'bitLength' " + bitLength + " not supported for SHA-3");
			}
		}

		public SHA3Digest() : this(256)
		{
		}

		public SHA3Digest(int bitLength) : base(checkBitLength(bitLength))
		{
		}

		public SHA3Digest(SHA3Digest source) : base(source)
		{
		}

		public override string getAlgorithmName()
		{
			return "SHA3-" + fixedOutputLength;
		}

		public override int doFinal(byte[] @out, int outOff)
		{
			absorbBits(0x02, 2);

			return base.doFinal(@out, outOff);
		}

		/*
		 * TODO Possible API change to support partial-byte suffixes.
		 */
		public override int doFinal(byte[] @out, int outOff, byte partialByte, int partialBits)
		{
			if (partialBits < 0 || partialBits > 7)
			{
				throw new IllegalArgumentException("'partialBits' must be in the range [0,7]");
			}

			int finalInput = (partialByte & ((1 << partialBits) - 1)) | (0x02 << partialBits);
			int finalBits = partialBits + 2;

			if (finalBits >= 8)
			{
				absorb(new byte[]{(byte)finalInput}, 0, 1);
				finalBits -= 8;
				finalInput = (int)((uint)finalInput >> 8);
			}

			return base.doFinal(@out, outOff, (byte)finalInput, finalBits);
		}
	}

}