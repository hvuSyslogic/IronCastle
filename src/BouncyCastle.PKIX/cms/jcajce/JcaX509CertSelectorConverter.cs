using org.bouncycastle.cert.selector.jcajce;

namespace org.bouncycastle.cms.jcajce
{


	public class JcaX509CertSelectorConverter : JcaX509CertSelectorConverter
	{
		public JcaX509CertSelectorConverter()
		{
		}

		public virtual X509CertSelector getCertSelector(KeyTransRecipientId recipientId)
		{
			return doConversion(recipientId.getIssuer(), recipientId.getSerialNumber(), recipientId.getSubjectKeyIdentifier());
		}

		public virtual X509CertSelector getCertSelector(SignerId signerId)
		{
			return doConversion(signerId.getIssuer(), signerId.getSerialNumber(), signerId.getSubjectKeyIdentifier());
		}
	}

}