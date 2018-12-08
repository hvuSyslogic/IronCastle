using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.esf
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public class OtherHashAlgAndValue : ASN1Object
	{
		private AlgorithmIdentifier hashAlgorithm;
		private ASN1OctetString hashValue;


		public static OtherHashAlgAndValue getInstance(object obj)
		{
			if (obj is OtherHashAlgAndValue)
			{
				return (OtherHashAlgAndValue) obj;
			}
			else if (obj != null)
			{
				return new OtherHashAlgAndValue(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private OtherHashAlgAndValue(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
			hashValue = ASN1OctetString.getInstance(seq.getObjectAt(1));
		}

		public OtherHashAlgAndValue(AlgorithmIdentifier hashAlgorithm, ASN1OctetString hashValue)
		{
			this.hashAlgorithm = hashAlgorithm;
			this.hashValue = hashValue;
		}

		public virtual AlgorithmIdentifier getHashAlgorithm()
		{
			return hashAlgorithm;
		}

		public virtual ASN1OctetString getHashValue()
		{
			return hashValue;
		}

		/// <summary>
		/// <pre>
		/// OtherHashAlgAndValue ::= SEQUENCE {
		///     hashAlgorithm AlgorithmIdentifier,
		///     hashValue OtherHashValue }
		/// 
		/// OtherHashValue ::= OCTET STRING
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(hashAlgorithm);
			v.add(hashValue);

			return new DERSequence(v);
		}
	}

}