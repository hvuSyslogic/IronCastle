namespace org.bouncycastle.cert.selector.jcajce
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	public class JcaSelectorConverter
	{
		public JcaSelectorConverter()
		{

		}

		public virtual X509CertificateHolderSelector getCertificateHolderSelector(X509CertSelector certSelector)
		{
			try
			{
				if (certSelector.getSubjectKeyIdentifier() != null)
				{
					return new X509CertificateHolderSelector(X500Name.getInstance(certSelector.getIssuerAsBytes()), certSelector.getSerialNumber(), ASN1OctetString.getInstance(certSelector.getSubjectKeyIdentifier()).getOctets());
				}
				else
				{
					return new X509CertificateHolderSelector(X500Name.getInstance(certSelector.getIssuerAsBytes()), certSelector.getSerialNumber());
				}
			}
			catch (IOException e)
			{
				throw new IllegalArgumentException("unable to convert issuer: " + e.Message);
			}
		}
	}

}