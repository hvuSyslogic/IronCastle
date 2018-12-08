namespace org.bouncycastle.cms
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using Arrays = org.bouncycastle.util.Arrays;
	using Selector = org.bouncycastle.util.Selector;

	/// <summary>
	/// a basic index for an originator.
	/// </summary>
	public class OriginatorId : Selector
	{
		private byte[] subjectKeyId;

		private X500Name issuer;
		private BigInteger serialNumber;

		/// <summary>
		/// Construct a signer ID with the value of a public key's subjectKeyId.
		/// </summary>
		/// <param name="subjectKeyId"> a subjectKeyId </param>
		public OriginatorId(byte[] subjectKeyId)
		{
			setSubjectKeyID(subjectKeyId);
		}

		private void setSubjectKeyID(byte[] subjectKeyId)
		{
			this.subjectKeyId = subjectKeyId;
		}

		/// <summary>
		/// Construct a signer ID based on the issuer and serial number of the signer's associated
		/// certificate.
		/// </summary>
		/// <param name="issuer"> the issuer of the signer's associated certificate. </param>
		/// <param name="serialNumber"> the serial number of the signer's associated certificate. </param>
		public OriginatorId(X500Name issuer, BigInteger serialNumber)
		{
			setIssuerAndSerial(issuer, serialNumber);
		}

		private void setIssuerAndSerial(X500Name issuer, BigInteger serialNumber)
		{
			this.issuer = issuer;
			this.serialNumber = serialNumber;
		}

		/// <summary>
		/// Construct a signer ID based on the issuer and serial number of the signer's associated
		/// certificate.
		/// </summary>
		/// <param name="issuer"> the issuer of the signer's associated certificate. </param>
		/// <param name="serialNumber"> the serial number of the signer's associated certificate. </param>
		/// <param name="subjectKeyId"> the subject key identifier to use to match the signers associated certificate. </param>
		public OriginatorId(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId)
		{
			setIssuerAndSerial(issuer, serialNumber);
			setSubjectKeyID(subjectKeyId);
		}

		public virtual X500Name getIssuer()
		{
			return issuer;
		}

		public virtual object clone()
		{
			return new OriginatorId(this.issuer, this.serialNumber, this.subjectKeyId);
		}

		public override int GetHashCode()
		{
			int code = Arrays.GetHashCode(subjectKeyId);

			if (this.serialNumber != null)
			{
				code ^= this.serialNumber.GetHashCode();
			}

			if (this.issuer != null)
			{
				code ^= this.issuer.GetHashCode();
			}

			return code;
		}

		public override bool Equals(object o)
		{
			if (!(o is OriginatorId))
			{
				return false;
			}

			OriginatorId id = (OriginatorId)o;

			return Arrays.areEqual(subjectKeyId, id.subjectKeyId) && equalsObj(this.serialNumber, id.serialNumber) && equalsObj(this.issuer, id.issuer);
		}

		private bool equalsObj(object a, object b)
		{
			return (a != null) ? a.Equals(b) : b == null;
		}

		public virtual bool match(object obj)
		{
			return false;
		}
	}

}