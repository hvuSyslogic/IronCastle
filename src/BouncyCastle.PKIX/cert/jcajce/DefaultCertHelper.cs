namespace org.bouncycastle.cert.jcajce
{

	public class DefaultCertHelper : CertHelper
	{
		public override CertificateFactory createCertificateFactory(string type)
		{
			return CertificateFactory.getInstance(type);
		}
	}

}