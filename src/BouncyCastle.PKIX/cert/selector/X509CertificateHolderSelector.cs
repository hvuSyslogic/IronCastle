namespace org.bouncycastle.cert.selector
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Arrays = org.bouncycastle.util.Arrays;
	using Selector = org.bouncycastle.util.Selector;

	/// <summary>
	/// a basic index for a X509CertificateHolder class
	/// </summary>
	public class X509CertificateHolderSelector : Selector
	{
		private byte[] subjectKeyId;

		private X500Name issuer;
		private BigInteger serialNumber;

		/// <summary>
		/// Construct a selector with the value of a public key's subjectKeyId.
		/// </summary>
		/// <param name="subjectKeyId"> a subjectKeyId </param>
		public X509CertificateHolderSelector(byte[] subjectKeyId) : this(null, null, subjectKeyId)
		{
		}

		/// <summary>
		/// Construct a signer ID based on the issuer and serial number of the signer's associated
		/// certificate.
		/// </summary>
		/// <param name="issuer"> the issuer of the signer's associated certificate. </param>
		/// <param name="serialNumber"> the serial number of the signer's associated certificate. </param>
		public X509CertificateHolderSelector(X500Name issuer, BigInteger serialNumber) : this(issuer, serialNumber, null)
		{
		}

		/// <summary>
		/// Construct a signer ID based on the issuer and serial number of the signer's associated
		/// certificate.
		/// </summary>
		/// <param name="issuer"> the issuer of the signer's associated certificate. </param>
		/// <param name="serialNumber"> the serial number of the signer's associated certificate. </param>
		/// <param name="subjectKeyId"> the subject key identifier to use to match the signers associated certificate. </param>
		public X509CertificateHolderSelector(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId)
		{
			this.issuer = issuer;
			this.serialNumber = serialNumber;
			this.subjectKeyId = subjectKeyId;
		}

		public virtual X500Name getIssuer()
		{
			return issuer;
		}

		public virtual BigInteger getSerialNumber()
		{
			return serialNumber;
		}

		public virtual byte[] getSubjectKeyIdentifier()
		{
			return Arrays.clone(subjectKeyId);
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
			if (!(o is X509CertificateHolderSelector))
			{
				return false;
			}

			X509CertificateHolderSelector id = (X509CertificateHolderSelector)o;

			return Arrays.areEqual(subjectKeyId, id.subjectKeyId) && equalsObj(this.serialNumber, id.serialNumber) && equalsObj(this.issuer, id.issuer);
		}

		private bool equalsObj(object a, object b)
		{
			return (a != null) ? a.Equals(b) : b == null;
		}

		public virtual bool match(object obj)
		{
			if (obj is X509CertificateHolder)
			{
				X509CertificateHolder certHldr = (X509CertificateHolder)obj;

				if (this.getSerialNumber() != null)
				{
					IssuerAndSerialNumber iAndS = new IssuerAndSerialNumber(certHldr.toASN1Structure());

					return iAndS.getName().Equals(this.issuer) && iAndS.getSerialNumber().getValue().Equals(this.serialNumber);
				}
				else if (subjectKeyId != null)
				{
					Extension ext = certHldr.getExtension(Extension.subjectKeyIdentifier);

					if (ext == null)
					{
						return Arrays.areEqual(subjectKeyId, MSOutlookKeyIdCalculator.calculateKeyId(certHldr.getSubjectPublicKeyInfo()));
					}

					byte[] subKeyID = ASN1OctetString.getInstance(ext.getParsedValue()).getOctets();

					return Arrays.areEqual(subjectKeyId, subKeyID);
				}
			}
			else if (obj is byte[])
			{
				return Arrays.areEqual(subjectKeyId, (byte[])obj);
			}

			return false;
		}

		public virtual object clone()
		{
			return new X509CertificateHolderSelector(this.issuer, this.serialNumber, this.subjectKeyId);
		}
	}

}