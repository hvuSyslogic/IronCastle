using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.esf
{

	/// <summary>
	/// <pre>
	/// CrlValidatedID ::= SEQUENCE {
	///   crlHash OtherHash,
	///   crlIdentifier CrlIdentifier OPTIONAL }
	/// </pre>
	/// </summary>
	public class CrlValidatedID : ASN1Object
	{

		private OtherHash crlHash;
		private CrlIdentifier crlIdentifier;

		public static CrlValidatedID getInstance(object obj)
		{
			if (obj is CrlValidatedID)
			{
				return (CrlValidatedID)obj;
			}
			else if (obj != null)
			{
				return new CrlValidatedID(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private CrlValidatedID(ASN1Sequence seq)
		{
			if (seq.size() < 1 || seq.size() > 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}
			this.crlHash = OtherHash.getInstance(seq.getObjectAt(0));
			if (seq.size() > 1)
			{
				this.crlIdentifier = CrlIdentifier.getInstance(seq.getObjectAt(1));
			}
		}

		public CrlValidatedID(OtherHash crlHash) : this(crlHash, null)
		{
		}

		public CrlValidatedID(OtherHash crlHash, CrlIdentifier crlIdentifier)
		{
			this.crlHash = crlHash;
			this.crlIdentifier = crlIdentifier;
		}

		public virtual OtherHash getCrlHash()
		{
			return this.crlHash;
		}

		public virtual CrlIdentifier getCrlIdentifier()
		{
			return this.crlIdentifier;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(this.crlHash.toASN1Primitive());
			if (null != this.crlIdentifier)
			{
				v.add(this.crlIdentifier.toASN1Primitive());
			}
			return new DERSequence(v);
		}
	}

}