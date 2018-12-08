namespace org.bouncycastle.jcajce.provider.asymmetric
{
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

	/// <summary>
	/// For some reason the class path project thinks that such a KeyFactory will exist.
	/// </summary>
	public class X509
	{
		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{

			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("KeyFactory.X.509", "org.bouncycastle.jcajce.provider.asymmetric.x509.KeyFactory");
				provider.addAlgorithm("Alg.Alias.KeyFactory.X509", "X.509");

				//
				// certificate factories.
				//
				provider.addAlgorithm("CertificateFactory.X.509", "org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory");
				provider.addAlgorithm("Alg.Alias.CertificateFactory.X509", "X.509");
			}
		}
	}

}