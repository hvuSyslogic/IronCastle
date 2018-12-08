namespace org.bouncycastle.gpg.keybox.jcajce
{

	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcaBlobVerifierBuilder
	{
		private JcaJceHelper helper = new DefaultJcaJceHelper();

		/// <summary>
		/// Default constructor.
		/// </summary>
		public JcaBlobVerifierBuilder()
		{
		}

		/// <summary>
		/// Sets the provider to use to obtain cryptographic primitives.
		/// </summary>
		/// <param name="provider"> the JCA provider to use. </param>
		/// <returns> the current builder. </returns>
		public virtual JcaBlobVerifierBuilder setProvider(Provider provider)
		{
			this.helper = new ProviderJcaJceHelper(provider);

			return this;
		}

		/// <summary>
		/// Sets the provider to use to obtain cryptographic primitives.
		/// </summary>
		/// <param name="providerName"> the name of the JCA provider to use. </param>
		/// <returns> the current builder. </returns>
		public virtual JcaBlobVerifierBuilder setProvider(string providerName)
		{
			this.helper = new NamedJcaJceHelper(providerName);

			return this;
		}

		public virtual JcaBlobVerifier build()
		{
			return new JcaBlobVerifier(helper);
		}
	}

}