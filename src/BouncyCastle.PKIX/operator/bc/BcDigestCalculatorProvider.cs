using org.bouncycastle.@operator.bc;

namespace org.bouncycastle.@operator.bc
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Digest = org.bouncycastle.crypto.Digest;
	using ExtendedDigest = org.bouncycastle.crypto.ExtendedDigest;

	public class BcDigestCalculatorProvider : DigestCalculatorProvider
	{
		private BcDigestProvider digestProvider = BcDefaultDigestProvider.INSTANCE;

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.DigestCalculator get(final org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithm) throws org.bouncycastle.operator.OperatorCreationException
		public virtual DigestCalculator get(AlgorithmIdentifier algorithm)
		{
			Digest dig = digestProvider.get(algorithm);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final DigestOutputStream stream = new DigestOutputStream(dig);
			DigestOutputStream stream = new DigestOutputStream(this, dig);

			return new DigestCalculatorAnonymousInnerClass(this, algorithm, stream);
		}

		public class DigestCalculatorAnonymousInnerClass : DigestCalculator
		{
			private readonly BcDigestCalculatorProvider outerInstance;

			private AlgorithmIdentifier algorithm;
			private BcDigestCalculatorProvider.DigestOutputStream stream;

			public DigestCalculatorAnonymousInnerClass(BcDigestCalculatorProvider outerInstance, AlgorithmIdentifier algorithm, BcDigestCalculatorProvider.DigestOutputStream stream)
			{
				this.outerInstance = outerInstance;
				this.algorithm = algorithm;
				this.stream = stream;
			}

			public AlgorithmIdentifier getAlgorithmIdentifier()
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
		}

		public class DigestOutputStream : OutputStream
		{
			private readonly BcDigestCalculatorProvider outerInstance;

			internal Digest dig;

			public DigestOutputStream(BcDigestCalculatorProvider outerInstance, Digest dig)
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