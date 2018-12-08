using org.bouncycastle.openpgp.@operator.jcajce;

namespace org.bouncycastle.openpgp.@operator.jcajce
{

	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	/// <summary>
	/// A builder for <seealso cref="PGPDigestCalculatorProvider"/> instances that obtain cryptographic primitives
	/// using the JCA API.
	/// <para>
	/// By default digest calculator providers obtained from this builder will use the default JCA
	/// algorithm lookup mechanisms (i.e. specifying no provider), but a specific provider can be
	/// specified prior to building.
	/// </para>
	/// </summary>
	public class JcaPGPDigestCalculatorProviderBuilder
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());

		/// <summary>
		/// Default constructor.
		/// </summary>
		public JcaPGPDigestCalculatorProviderBuilder()
		{
		}

		/// <summary>
		/// Sets the provider to use to obtain cryptographic primitives.
		/// </summary>
		/// <param name="provider"> the JCA provider to use. </param>
		/// <returns> the current builder. </returns>
		public virtual JcaPGPDigestCalculatorProviderBuilder setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		/// <summary>
		/// Sets the provider to use to obtain cryptographic primitives.
		/// </summary>
		/// <param name="providerName"> the name of the JCA provider to use. </param>
		/// <returns> the current builder. </returns>
		public virtual JcaPGPDigestCalculatorProviderBuilder setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		/// <summary>
		/// Constructs a new PGPDigestCalculatorProvider
		/// </summary>
		/// <returns> a PGPDigestCalculatorProvider that will use the JCA algorithm lookup strategy
		///         configured on this builder. </returns>
		/// <exception cref="PGPException"> if an error occurs constructing the digest calculator provider. </exception>
		public virtual PGPDigestCalculatorProvider build()
		{
			return new PGPDigestCalculatorProviderAnonymousInnerClass(this);
		}

		public class PGPDigestCalculatorProviderAnonymousInnerClass : PGPDigestCalculatorProvider
		{
			private readonly JcaPGPDigestCalculatorProviderBuilder outerInstance;

			public PGPDigestCalculatorProviderAnonymousInnerClass(JcaPGPDigestCalculatorProviderBuilder outerInstance)
			{
				this.outerInstance = outerInstance;
			}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.openpgp.operator.PGPDigestCalculator get(final int algorithm) throws org.bouncycastle.openpgp.PGPException
			public PGPDigestCalculator get(int algorithm)
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final DigestOutputStream stream;
				DigestOutputStream stream;
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.security.MessageDigest dig;
				MessageDigest dig;

				try
				{
					dig = outerInstance.helper.createDigest(algorithm);

					stream = new DigestOutputStream(outerInstance, dig);
				}
				catch (GeneralSecurityException e)
				{
					throw new PGPException("exception on setup: " + e, e);
				}

				return new PGPDigestCalculatorAnonymousInnerClass(this, algorithm, stream, dig);
			}

			public class PGPDigestCalculatorAnonymousInnerClass : PGPDigestCalculator
			{
				private readonly PGPDigestCalculatorProviderAnonymousInnerClass outerInstance;

				private int algorithm;
				private JcaPGPDigestCalculatorProviderBuilder.DigestOutputStream stream;
				private MessageDigest dig;

				public PGPDigestCalculatorAnonymousInnerClass(PGPDigestCalculatorProviderAnonymousInnerClass outerInstance, int algorithm, JcaPGPDigestCalculatorProviderBuilder.DigestOutputStream stream, MessageDigest dig)
				{
					this.outerInstance = outerInstance;
					this.algorithm = algorithm;
					this.stream = stream;
					this.dig = dig;
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
		}

		public class DigestOutputStream : OutputStream
		{
			private readonly JcaPGPDigestCalculatorProviderBuilder outerInstance;

			internal MessageDigest dig;

			public DigestOutputStream(JcaPGPDigestCalculatorProviderBuilder outerInstance, MessageDigest dig)
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