namespace org.bouncycastle.pkix.jcajce
{

	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;

	public interface PKIXJcaJceHelper : JcaJceHelper
	{
		CertPathBuilder createCertPathBuilder(string type);
	}

}