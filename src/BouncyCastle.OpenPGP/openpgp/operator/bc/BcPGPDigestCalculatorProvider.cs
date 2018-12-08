using org.bouncycastle.openpgp.@operator.bc;

namespace org.bouncycastle.openpgp.@operator.bc
{

	using Digest = org.bouncycastle.crypto.Digest;

	public class BcPGPDigestCalculatorProvider : PGPDigestCalculatorProvider
	{
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.openpgp.operator.PGPDigestCalculator get(final int algorithm) throws org.bouncycastle.openpgp.PGPException
		public virtual PGPDigestCalculator get(int algorithm)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.Digest dig = BcImplProvider.createDigest(algorithm);
			Digest dig = BcImplProvider.createDigest(algorithm);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final DigestOutputStream stream = new DigestOutputStream(dig);
			DigestOutputStream stream = new DigestOutputStream(this, dig);

			return new PGPDigestCalculatorAnonymousInnerClass(this, algorithm, dig, stream);
		}

		public class PGPDigestCalculatorAnonymousInnerClass : PGPDigestCalculator
		{
			private readonly BcPGPDigestCalculatorProvider outerInstance;

			private int algorithm;
			private Digest dig;
			private BcPGPDigestCalculatorProvider.DigestOutputStream stream;

			public PGPDigestCalculatorAnonymousInnerClass(BcPGPDigestCalculatorProvider outerInstance, int algorithm, Digest dig, BcPGPDigestCalculatorProvider.DigestOutputStream stream)
			{
				this.outerInstance = outerInstance;
				this.algorithm = algorithm;
				this.dig = dig;
				this.stream = stream;
			}

			public int getAlgorithm()
			{
				return algorithm;
			}

			public OutputStream getOutputStream()
			{
				return stream;
			}

			public byte[] getDigest()
			{
				return stream.getDigest();
			}

			public void reset()
			{
				dig.reset();
			}
		}

		public class DigestOutputStream : OutputStream
		{
			private readonly BcPGPDigestCalculatorProvider outerInstance;

			internal Digest dig;

			public DigestOutputStream(BcPGPDigestCalculatorProvider outerInstance, Digest dig)
			{
				this.outerInstance = outerInstance;
				this.dig = dig;
			}

			public virtual void write(byte[] bytes, int off, int len)
			{
				dig.update(bytes, off, len);
			}

			public virtual void write(byte[] bytes)
			{
				dig.update(bytes, 0, bytes.Length);
			}

			public virtual void write(int b)
			{
				dig.update((byte)b);
			}

			public virtual byte[] getDigest()
			{
				byte[] d = new byte[dig.getDigestSize()];

				dig.doFinal(d, 0);

				return d;
			}
		}
	}
}