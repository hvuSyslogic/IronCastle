namespace org.bouncycastle.cms.jcajce
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	public class JceKeyTransRecipientId : KeyTransRecipientId
	{
		/// <summary>
		/// Construct a recipient id based on the issuer, serial number and subject key identifier (if present) of the passed in
		/// certificate.
		/// </summary>
		/// <param name="certificate"> certificate providing the issue and serial number and subject key identifier. </param>
		public JceKeyTransRecipientId(X509Certificate certificate) : base(convertPrincipal(certificate.getIssuerX500Principal()), certificate.getSerialNumber(), CMSUtils.getSubjectKeyId(certificate))
		{
		}

		/// <summary>
		/// Construct a recipient id based on the provided issuer and serial number..
		/// </summary>
		/// <param name="issuer"> the issuer to use. </param>
		/// <param name="serialNumber">  the serial number to use. </param>
		public JceKeyTransRecipientId(X500Principal issuer, BigInteger serialNumber) : base(convertPrincipal(issuer), serialNumber)
		{
		}

		/// <summary>
		/// Construct a recipient id based on the provided issuer, serial number, and subjectKeyId..
		/// </summary>
		/// <param name="issuer"> the issuer to use. </param>
		/// <param name="serialNumber">  the serial number to use. </param>
		/// <param name="subjectKeyId"> the subject key ID to use. </param>
		public JceKeyTransRecipientId(X500Principal issuer, BigInteger serialNumber, byte[] subjectKeyId) : base(convertPrincipal(issuer), serialNumber, subjectKeyId)
		{
		}

		private static X500Name convertPrincipal(X500Principal issuer)
		{
			if (issuer == null)
			{
				return null;
			}

			return X500Name.getInstance(issuer.getEncoded());
		}
	}

}