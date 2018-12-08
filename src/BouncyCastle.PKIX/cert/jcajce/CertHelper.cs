namespace org.bouncycastle.cert.jcajce
{

	public abstract class CertHelper
	{
		public virtual CertificateFactory getCertificateFactory(string type)
		{
			return createCertificateFactory(type);
		}

		public abstract CertificateFactory createCertificateFactory(string type);
	}

}