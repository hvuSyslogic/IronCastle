namespace org.bouncycastle.pkix.jcajce
{

	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;

	public class PKIXNamedJcaJceHelper : NamedJcaJceHelper, PKIXJcaJceHelper
	{
		public PKIXNamedJcaJceHelper(string providerName) : base(providerName)
		{
		}

		public virtual CertPathBuilder createCertPathBuilder(string type)
		{
			return CertPathBuilder.getInstance(type, providerName);
		}
	}

}