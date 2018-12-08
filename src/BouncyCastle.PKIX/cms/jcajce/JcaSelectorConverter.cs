namespace org.bouncycastle.cms.jcajce
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	public class JcaSelectorConverter
	{
		public JcaSelectorConverter()
		{

		}

		public virtual SignerId getSignerId(X509CertSelector certSelector)
		{
			try
			{
				if (certSelector.getSubjectKeyIdentifier() != null)
				{
					return new SignerId(X500Name.getInstance(certSelector.getIssuerAsBytes()), certSelector.getSerialNumber(), ASN1OctetString.getInstance(certSelector.getSubjectKeyIdentifier()).getOctets());
				}
				else
				{
					return new SignerId(X500Name.getInstance(certSelector.getIssuerAsBytes()), certSelector.getSerialNumber());
				}
			}
			catch (IOException e)
			{
				throw new IllegalArgumentException("unable to convert issuer: " + e.Message);
			}
		}

		public virtual KeyTransRecipientId getKeyTransRecipientId(X509CertSelector certSelector)
		{
			try
			{
				if (certSelector.getSubjectKeyIdentifier() != null)
				{
					return new KeyTransRecipientId(X500Name.getInstance(certSelector.getIssuerAsBytes()), certSelector.getSerialNumber(), ASN1OctetString.getInstance(certSelector.getSubjectKeyIdentifier()).getOctets());
				}
				else
				{
					return new KeyTransRecipientId(X500Name.getInstance(certSelector.getIssuerAsBytes()), certSelector.getSerialNumber());
				}
			}
			catch (IOException e)
			{
				throw new IllegalArgumentException("unable to convert issuer: " + e.Message);
			}
		}
	}

}