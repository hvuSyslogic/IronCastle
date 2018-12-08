namespace org.bouncycastle.est.jcajce
{

	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using JcaDigestCalculatorProviderBuilder = org.bouncycastle.@operator.jcajce.JcaDigestCalculatorProviderBuilder;

	/// <summary>
	/// Builder for HttpAuth operator that handles digest auth using a JCA provider.
	/// </summary>
	public class JcaHttpAuthBuilder
	{
		private JcaDigestCalculatorProviderBuilder providerBuilder = new JcaDigestCalculatorProviderBuilder();

		private readonly string realm;
		private readonly string username;
		private readonly char[] password;
		private SecureRandom random = new SecureRandom();

		/// <summary>
		/// Base constructor for digest auth.
		/// </summary>
		/// <param name="username"> user id. </param>
		/// <param name="password"> user's password. </param>
		public JcaHttpAuthBuilder(string username, char[] password) : this(null, username, password)
		{
		}

		/// <summary>
		/// Base constructor for digest auth with an expected realm.
		/// </summary>
		/// <param name="realm">    expected server realm. </param>
		/// <param name="username"> user id. </param>
		/// <param name="password"> user's password. </param>
		public JcaHttpAuthBuilder(string realm, string username, char[] password)
		{
			this.realm = realm;
			this.username = username;
			this.password = password;
		}

		/// <summary>
		/// Set the provider to use to provide the needed message digests.
		/// </summary>
		/// <param name="provider"> provider to use. </param>
		/// <returns> this builder instance. </returns>
		public virtual JcaHttpAuthBuilder setProvider(Provider provider)
		{
			this.providerBuilder.setProvider(provider);

			return this;
		}

		/// <summary>
		/// Set the provider to use to provide the needed message digests.
		/// </summary>
		/// <param name="providerName"> the name provider to use. </param>
		/// <returns> this builder instance. </returns>
		public virtual JcaHttpAuthBuilder setProvider(string providerName)
		{
			this.providerBuilder.setProvider(providerName);

			return this;
		}

		/// <summary>
		/// Set the SecureRandom to be used as a source of nonces.
		/// </summary>
		/// <param name="random"> the secure random to use as a nonce generator. </param>
		/// <returns> this builder instance. </returns>
		public virtual JcaHttpAuthBuilder setNonceGenerator(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		/// <summary>
		/// Return a HttpAuth implementing digest auth for the user, password, and realm combination.
		/// </summary>
		/// <returns> a HttpAuth object. </returns>
		/// <exception cref="OperatorCreationException"> if there is an issue setting up access to digest operators. </exception>
		public virtual HttpAuth build()
		{
			return new HttpAuth(realm, username, password, random, providerBuilder.build());
		}
	}

}