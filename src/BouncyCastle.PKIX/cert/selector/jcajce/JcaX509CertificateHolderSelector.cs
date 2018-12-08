namespace org.bouncycastle.cert.selector.jcajce
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using Extension = org.bouncycastle.asn1.x509.Extension;

	public class JcaX509CertificateHolderSelector : X509CertificateHolderSelector
	{
		/// <summary>
		/// Construct a signer identifier based on the issuer, serial number and subject key identifier (if present) of the passed in
		/// certificate.
		/// </summary>
		/// <param name="certificate"> certificate providing the issue and serial number and subject key identifier. </param>
		public JcaX509CertificateHolderSelector(X509Certificate certificate) : base(convertPrincipal(certificate.getIssuerX500Principal()), certificate.getSerialNumber(), getSubjectKeyId(certificate))
		{
		}

		/// <summary>
		/// Construct a signer identifier based on the provided issuer and serial number..
		/// </summary>
		/// <param name="issuer"> the issuer to use. </param>
		/// <param name="serialNumber">  the serial number to use. </param>
		public JcaX509CertificateHolderSelector(X500Principal issuer, BigInteger serialNumber) : base(convertPrincipal(issuer), serialNumber)
		{
		}

		/// <summary>
		/// Construct a signer identifier based on the provided issuer, serial number, and subjectKeyId..
		/// </summary>
		/// <param name="issuer"> the issuer to use. </param>
		/// <param name="serialNumber">  the serial number to use. </param>
		/// <param name="subjectKeyId"> the subject key ID to use. </param>
		public JcaX509CertificateHolderSelector(X500Principal issuer, BigInteger serialNumber, byte[] subjectKeyId) : base(convertPrincipal(issuer), serialNumber, subjectKeyId)
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

		private static byte[] getSubjectKeyId(X509Certificate cert)
		{
			byte[] ext = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());

			if (ext != null)
			{
				return ASN1OctetString.getInstance(ASN1OctetString.getInstance(ext).getOctets()).getOctets();
			}
			else
			{
				return null;
			}
		}
	}

}