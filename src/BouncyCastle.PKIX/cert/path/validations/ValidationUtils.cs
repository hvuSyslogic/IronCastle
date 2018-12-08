namespace org.bouncycastle.cert.path.validations
{

	public class ValidationUtils
	{
		internal static bool isSelfIssued(X509CertificateHolder cert)
		{
			return cert.getSubject().Equals(cert.getIssuer());
		}
	}

}