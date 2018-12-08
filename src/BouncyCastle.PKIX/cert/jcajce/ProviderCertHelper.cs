namespace org.bouncycastle.cert.jcajce
{

	public class ProviderCertHelper : CertHelper
	{
		private readonly Provider provider;

		public ProviderCertHelper(Provider provider)
		{
			this.provider = provider;
		}

		public override CertificateFactory createCertificateFactory(string type)
		{
			return CertificateFactory.getInstance(type, provider);
		}
	}
}