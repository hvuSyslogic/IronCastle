namespace org.bouncycastle.cert.selector.jcajce
{

	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	public class JcaX509CertSelectorConverter
	{
		public JcaX509CertSelectorConverter()
		{
		}

		public virtual X509CertSelector doConversion(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyIdentifier)
		{
			X509CertSelector selector = new X509CertSelector();

			if (issuer != null)
			{
				try
				{
					selector.setIssuer(issuer.getEncoded());
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("unable to convert issuer: " + e.Message);
				}
			}

			if (serialNumber != null)
			{
				selector.setSerialNumber(serialNumber);
			}

			if (subjectKeyIdentifier != null)
			{
				try
				{
					selector.setSubjectKeyIdentifier((new DEROctetString(subjectKeyIdentifier)).getEncoded());
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("unable to convert issuer: " + e.Message);
				}
			}

			return selector;
		}

		public virtual X509CertSelector getCertSelector(X509CertificateHolderSelector holderSelector)
		{
			return doConversion(holderSelector.getIssuer(), holderSelector.getSerialNumber(), holderSelector.getSubjectKeyIdentifier());
		}
	}

}