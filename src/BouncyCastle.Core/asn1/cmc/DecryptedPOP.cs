using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.cmc
{
		
	/// <summary>
	/// <pre>
	///      id-cmc-decryptedPOP OBJECT IDENTIFIER ::= {id-cmc 10}
	/// 
	///       DecryptedPOP ::= SEQUENCE {
	///            bodyPartID      BodyPartID,
	///            thePOPAlgID     AlgorithmIdentifier,
	///            thePOP          OCTET STRING
	///       }
	/// </pre>
	/// </summary>
	public class DecryptedPOP : ASN1Object
	{
		private readonly BodyPartID bodyPartID;
		private readonly AlgorithmIdentifier thePOPAlgID;
		private readonly byte[] thePOP;

		public DecryptedPOP(BodyPartID bodyPartID, AlgorithmIdentifier thePOPAlgID, byte[] thePOP)
		{
			this.bodyPartID = bodyPartID;
			this.thePOPAlgID = thePOPAlgID;
			this.thePOP = Arrays.clone(thePOP);
		}

		private DecryptedPOP(ASN1Sequence seq)
		{
			if (seq.size() != 3)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
			this.thePOPAlgID = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
			this.thePOP = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());
		}


		public static DecryptedPOP getInstance(object o)
		{
			if (o is DecryptedPOP)
			{
				return (DecryptedPOP)o;
			}

			if (o != null)
			{
				return new DecryptedPOP(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual BodyPartID getBodyPartID()
		{
			return bodyPartID;
		}

		public virtual AlgorithmIdentifier getThePOPAlgID()
		{
			return thePOPAlgID;
		}

		public virtual byte[] getThePOP()
		{
			return Arrays.clone(thePOP);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(bodyPartID);
			v.add(thePOPAlgID);
			v.add(new DEROctetString(thePOP));

			return new DERSequence(v);
		}
	}

}