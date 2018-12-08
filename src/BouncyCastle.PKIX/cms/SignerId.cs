namespace org.bouncycastle.cms
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using X509CertificateHolderSelector = org.bouncycastle.cert.selector.X509CertificateHolderSelector;
	using Selector = org.bouncycastle.util.Selector;

	/// <summary>
	/// a basic index for a signer.
	/// </summary>
	public class SignerId : Selector
	{
		private X509CertificateHolderSelector baseSelector;

		private SignerId(X509CertificateHolderSelector baseSelector)
		{
			this.baseSelector = baseSelector;
		}

		/// <summary>
		/// Construct a signer ID with the value of a public key's subjectKeyId.
		/// </summary>
		/// <param name="subjectKeyId"> a subjectKeyId </param>
		public SignerId(byte[] subjectKeyId) : this(null, null, subjectKeyId)
		{
		}

		/// <summary>
		/// Construct a signer ID based on the issuer and serial number of the signer's associated
		/// certificate.
		/// </summary>
		/// <param name="issuer"> the issuer of the signer's associated certificate. </param>
		/// <param name="serialNumber"> the serial number of the signer's associated certificate. </param>
		public SignerId(X500Name issuer, BigInteger serialNumber) : this(issuer, serialNumber, null)
		{
		}

		/// <summary>
		/// Construct a signer ID based on the issuer and serial number of the signer's associated
		/// certificate.
		/// </summary>
		/// <param name="issuer"> the issuer of the signer's associated certificate. </param>
		/// <param name="serialNumber"> the serial number of the signer's associated certificate. </param>
		/// <param name="subjectKeyId"> the subject key identifier to use to match the signers associated certificate. </param>
		public SignerId(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId) : this(new X509CertificateHolderSelector(issuer, serialNumber, subjectKeyId))
		{
		}

		public virtual X500Name getIssuer()
		{
			return baseSelector.getIssuer();
		}

		public virtual BigInteger getSerialNumber()
		{
			return baseSelector.getSerialNumber();
		}

		public virtual byte[] getSubjectKeyIdentifier()
		{
			return baseSelector.getSubjectKeyIdentifier();
		}

		public override int GetHashCode()
		{
			return baseSelector.GetHashCode();
		}

		public override bool Equals(object o)
		{
			if (!(o is SignerId))
			{
				return false;
			}

			SignerId id = (SignerId)o;

			return this.baseSelector.Equals(id.baseSelector);
		}

		public virtual bool match(object obj)
		{
			if (obj is SignerInformation)
			{
				return ((SignerInformation)obj).getSID().Equals(this);
			}

			return baseSelector.match(obj);
		}

		public virtual object clone()
		{
			return new SignerId(this.baseSelector);
		}
	}

}