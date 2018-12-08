namespace org.bouncycastle.cert.cmp
{
	using CertConfirmContent = org.bouncycastle.asn1.cmp.CertConfirmContent;
	using CertStatus = org.bouncycastle.asn1.cmp.CertStatus;
	using DefaultDigestAlgorithmIdentifierFinder = org.bouncycastle.@operator.DefaultDigestAlgorithmIdentifierFinder;
	using DigestAlgorithmIdentifierFinder = org.bouncycastle.@operator.DigestAlgorithmIdentifierFinder;

	public class CertificateConfirmationContent
	{
		private DigestAlgorithmIdentifierFinder digestAlgFinder;
		private CertConfirmContent content;

		public CertificateConfirmationContent(CertConfirmContent content) : this(content, new DefaultDigestAlgorithmIdentifierFinder())
		{
		}

		public CertificateConfirmationContent(CertConfirmContent content, DigestAlgorithmIdentifierFinder digestAlgFinder)
		{
			this.digestAlgFinder = digestAlgFinder;
			this.content = content;
		}

		public virtual CertConfirmContent toASN1Structure()
		{
			return content;
		}

		public virtual CertificateStatus[] getStatusMessages()
		{
			CertStatus[] statusArray = content.toCertStatusArray();
			CertificateStatus[] ret = new CertificateStatus[statusArray.Length];

			for (int i = 0; i != ret.Length; i++)
			{
				ret[i] = new CertificateStatus(digestAlgFinder, statusArray[i]);
			}

			return ret;
		}
	}

}