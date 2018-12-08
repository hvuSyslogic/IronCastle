using org.bouncycastle.asn1.oiw;

namespace org.bouncycastle.asn1.esf
{
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// <pre>
	/// OtherHash ::= CHOICE {
	///    sha1Hash  OtherHashValue, -- This contains a SHA-1 hash
	///   otherHash  OtherHashAlgAndValue
	///  }
	/// </pre>
	/// </summary>
	public class OtherHash : ASN1Object, ASN1Choice
	{

		private ASN1OctetString sha1Hash;
		private OtherHashAlgAndValue otherHash;

		public static OtherHash getInstance(object obj)
		{
			if (obj is OtherHash)
			{
				return (OtherHash)obj;
			}
			if (obj is ASN1OctetString)
			{
				return new OtherHash((ASN1OctetString)obj);
			}
			return new OtherHash(OtherHashAlgAndValue.getInstance(obj));
		}

		private OtherHash(ASN1OctetString sha1Hash)
		{
			this.sha1Hash = sha1Hash;
		}

		public OtherHash(OtherHashAlgAndValue otherHash)
		{
			this.otherHash = otherHash;
		}

		public OtherHash(byte[] sha1Hash)
		{
			this.sha1Hash = new DEROctetString(sha1Hash);
		}

		public virtual AlgorithmIdentifier getHashAlgorithm()
		{
			if (null == this.otherHash)
			{
				return new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1);
			}
			return this.otherHash.getHashAlgorithm();
		}

		public virtual byte[] getHashValue()
		{
			if (null == this.otherHash)
			{
				return this.sha1Hash.getOctets();
			}
			return this.otherHash.getHashValue().getOctets();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			if (null == this.otherHash)
			{
				return this.sha1Hash;
			}
			return this.otherHash.toASN1Primitive();
		}
	}

}