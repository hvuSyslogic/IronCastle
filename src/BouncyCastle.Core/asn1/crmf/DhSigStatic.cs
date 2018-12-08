using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.crmf
{
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// From RFC 2875 for Diffie-Hellman POP.
	/// <pre>
	///     DhSigStatic ::= SEQUENCE {
	///         IssuerAndSerial IssuerAndSerialNumber OPTIONAL,
	///         hashValue       MessageDigest
	///     }
	/// </pre>
	/// </summary>
	public class DhSigStatic : ASN1Object
	{
		private readonly IssuerAndSerialNumber issuerAndSerial;
		private readonly ASN1OctetString hashValue;

		public DhSigStatic(byte[] hashValue) : this(null, hashValue)
		{
		}

		public DhSigStatic(IssuerAndSerialNumber issuerAndSerial, byte[] hashValue)
		{
			this.issuerAndSerial = issuerAndSerial;
			this.hashValue = new DEROctetString(Arrays.clone(hashValue));
		}

		public static DhSigStatic getInstance(object o)
		{
			if (o is DhSigStatic)
			{
				return (DhSigStatic)o;
			}
			else if (o != null)
			{
				return new DhSigStatic(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		private DhSigStatic(ASN1Sequence seq)
		{
			if (seq.size() == 1)
			{
				issuerAndSerial = null;
				hashValue = ASN1OctetString.getInstance(seq.getObjectAt(0));
			}
			else if (seq.size() == 2)
			{
				issuerAndSerial = IssuerAndSerialNumber.getInstance(seq.getObjectAt(0));
				hashValue = ASN1OctetString.getInstance(seq.getObjectAt(1));
			}
			else
			{
				throw new IllegalArgumentException("sequence wrong length for DhSigStatic");
			}
		}

		public virtual IssuerAndSerialNumber getIssuerAndSerial()
		{
			return issuerAndSerial;
		}

		public virtual byte[] getHashValue()
		{
			return Arrays.clone(hashValue.getOctets());
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (issuerAndSerial != null)
			{
				v.add(issuerAndSerial);
			}

			v.add(hashValue);

			return new DERSequence(v);
		}
	}

}