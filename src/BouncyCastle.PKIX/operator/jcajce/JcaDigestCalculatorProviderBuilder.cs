using org.bouncycastle.@operator.jcajce;

namespace org.bouncycastle.@operator.jcajce
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcaDigestCalculatorProviderBuilder
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());

		public JcaDigestCalculatorProviderBuilder()
		{
		}

		public virtual JcaDigestCalculatorProviderBuilder setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual JcaDigestCalculatorProviderBuilder setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		public virtual DigestCalculatorProvider build()
		{
			return new DigestCalculatorProviderAnonymousInnerClass(this);
		}

		public class DigestCalculatorProviderAnonymousInnerClass : DigestCalculatorProvider
		{
			private readonly JcaDigestCalculatorProviderBuilder outerInstance;

			public DigestCalculatorProviderAnonymousInnerClass(JcaDigestCalculatorProviderBuilder outerInstance)
			{
				this.outerInstance = outerInstance;
			}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.DigestCalculator get(final org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithm) throws org.bouncycastle.operator.OperatorCreationException
			public DigestCalculator get(AlgorithmIdentifier algorithm)
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final DigestOutputStream stream;
				DigestOutputStream stream;

				try
				{
					MessageDigest dig = outerInstance.helper.createDigest(algorithm);

					stream = new DigestOutputStream(outerInstance, dig);
				}
				catch (GeneralSecurityException e)
				{
					throw new OperatorCreationException("exception on setup: " + e, e);
				}

				return new DigestCalculatorAnonymousInnerClass(this, algorithm, stream);
			}

			public class DigestCalculatorAnonymousInnerClass : DigestCalculator
			{
				private readonly DigestCalculatorProviderAnonymousInnerClass outerInstance;

				private AlgorithmIdentifier algorithm;
				private JcaDigestCalculatorProviderBuilder.DigestOutputStream stream;

				public DigestCalculatorAnonymousInnerClass(DigestCalculatorProviderAnonymousInnerClass outerInstance, AlgorithmIdentifier algorithm, JcaDigestCalculatorProviderBuilder.DigestOutputStream stream)
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
		}

		public class DigestOutputStream : OutputStream
		{
			private readonly JcaDigestCalculatorProviderBuilder outerInstance;

			internal MessageDigest dig;

			public DigestOutputStream(JcaDigestCalculatorProviderBuilder outerInstance, MessageDigest dig)
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
			   dig.update(bytes);
			}

			public virtual void write(int b)
			{
			   dig.update((byte)b);
			}

			public virtual byte[] getDigest()
			{
				return dig.digest();
			}
		}
	}
}