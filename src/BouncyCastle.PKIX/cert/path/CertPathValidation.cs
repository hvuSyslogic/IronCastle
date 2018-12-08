namespace org.bouncycastle.cert.path
{
	using Memoable = org.bouncycastle.util.Memoable;

	public interface CertPathValidation : Memoable
	{
		void validate(CertPathValidationContext context, X509CertificateHolder certificate);
	}

}