namespace org.bouncycastle.cert.jcajce
{

	public class NamedCertHelper : CertHelper
	{
		private readonly string providerName;

		public NamedCertHelper(string providerName)
		{
			this.providerName = providerName;
		}

		public override CertificateFactory createCertificateFactory(string type)
		{
			return CertificateFactory.getInstance(type, providerName);
		}
	}
}