namespace org.bouncycastle.pkix.jcajce
{

	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;

	public class PKIXDefaultJcaJceHelper : DefaultJcaJceHelper, PKIXJcaJceHelper
	{
		public PKIXDefaultJcaJceHelper() : base()
		{
		}

		public virtual CertPathBuilder createCertPathBuilder(string type)
		{
			return CertPathBuilder.getInstance(type);
		}
	}

}