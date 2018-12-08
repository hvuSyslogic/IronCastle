namespace org.bouncycastle.gpg.keybox.jcajce
{

	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;

	public class JcaKeyBoxBuilder
	{
		private JcaJceHelper helper = new DefaultJcaJceHelper();

		/// <summary>
		/// Default constructor.
		/// </summary>
		public JcaKeyBoxBuilder()
		{
		}

		/// <summary>
		/// Sets the provider to use to obtain cryptographic primitives.
		/// </summary>
		/// <param name="provider"> the JCA provider to use. </param>
		/// <returns> the current builder. </returns>
		public virtual JcaKeyBoxBuilder setProvider(Provider provider)
		{
			this.helper = new ProviderJcaJceHelper(provider);

			return this;
		}

		/// <summary>
		/// Sets the provider to use to obtain cryptographic primitives.
		/// </summary>
		/// <param name="providerName"> the name of the JCA provider to use. </param>
		/// <returns> the current builder. </returns>
		public virtual JcaKeyBoxBuilder setProvider(string providerName)
		{
			this.helper = new NamedJcaJceHelper(providerName);

			return this;
		}

		public virtual JcaKeyBox build(InputStream input)
		{
			return new JcaKeyBox(input, new JcaKeyFingerprintCalculator(), new JcaBlobVerifier(helper));
		}

		public virtual JcaKeyBox build(byte[] encoding)
		{
			return new JcaKeyBox(encoding, new JcaKeyFingerprintCalculator(), new JcaBlobVerifier(helper));
		}
	}

}