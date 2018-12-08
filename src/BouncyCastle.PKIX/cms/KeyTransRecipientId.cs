namespace org.bouncycastle.cms
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using X509CertificateHolderSelector = org.bouncycastle.cert.selector.X509CertificateHolderSelector;

	public class KeyTransRecipientId : RecipientId
	{
		private X509CertificateHolderSelector baseSelector;

		private KeyTransRecipientId(X509CertificateHolderSelector baseSelector) : base(keyTrans)
		{

			this.baseSelector = baseSelector;
		}

		/// <summary>
		/// Construct a key trans recipient ID with the value of a public key's subjectKeyId.
		/// </summary>
		/// <param name="subjectKeyId"> a subjectKeyId </param>
		public KeyTransRecipientId(byte[] subjectKeyId) : this(null, null, subjectKeyId)
		{
		}

		/// <summary>
		/// Construct a key trans recipient ID based on the issuer and serial number of the recipient's associated
		/// certificate.
		/// </summary>
		/// <param name="issuer"> the issuer of the recipient's associated certificate. </param>
		/// <param name="serialNumber"> the serial number of the recipient's associated certificate. </param>
		public KeyTransRecipientId(X500Name issuer, BigInteger serialNumber) : this(issuer, serialNumber, null)
		{
		}

		/// <summary>
		/// Construct a key trans recipient ID based on the issuer and serial number of the recipient's associated
		/// certificate.
		/// </summary>
		/// <param name="issuer"> the issuer of the recipient's associated certificate. </param>
		/// <param name="serialNumber"> the serial number of the recipient's associated certificate. </param>
		/// <param name="subjectKeyId"> the subject key identifier to use to match the recipients associated certificate. </param>
		public KeyTransRecipientId(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId) : this(new X509CertificateHolderSelector(issuer, serialNumber, subjectKeyId))
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
			if (!(o is KeyTransRecipientId))
			{
				return false;
			}

			KeyTransRecipientId id = (KeyTransRecipientId)o;

			return this.baseSelector.Equals(id.baseSelector);
		}

		public override object clone()
		{
			return new KeyTransRecipientId(this.baseSelector);
		}

		public virtual bool match(object obj)
		{
			if (obj is KeyTransRecipientInformation)
			{
				return ((KeyTransRecipientInformation)obj).getRID().Equals(this);
			}

			return baseSelector.match(obj);
		}
	}

}