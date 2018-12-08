namespace org.bouncycastle.pkix.jcajce
{

	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class PKIXProviderJcaJceHelper : ProviderJcaJceHelper, PKIXJcaJceHelper
	{
		public PKIXProviderJcaJceHelper(Provider provider) : base(provider)
		{
		}

		public virtual CertPathBuilder createCertPathBuilder(string type)
		{
			return CertPathBuilder.getInstance(type, provider);
		}
	}

}