using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.digests
{
	using Memoable = org.bouncycastle.util.Memoable;

	/// <summary>
	/// implementation of GOST R 34.11-2012 256-bit
	/// </summary>
	public sealed class GOST3411_2012_256Digest : GOST3411_2012Digest
	{
		private static readonly byte[] IV = new byte[] {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

		public GOST3411_2012_256Digest() : base(IV)
		{
		}

		public GOST3411_2012_256Digest(GOST3411_2012_256Digest other) : base(IV)
		{
			reset(other);
		}

		public override string getAlgorithmName()
		{
			return "GOST3411-2012-256";
		}

		public override int getDigestSize()
		{
			return 32;
		}

		public override int doFinal(byte[] @out, int outOff)
		{
			byte[] result = new byte[64];
			base.doFinal(result, 0);

			JavaSystem.arraycopy(result, 32, @out, outOff, 32);

			return 32;
		}

		public override Memoable copy()
		{
			return new GOST3411_2012_256Digest(this);
		}
	}

}