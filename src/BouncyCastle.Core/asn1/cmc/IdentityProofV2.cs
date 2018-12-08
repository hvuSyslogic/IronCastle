using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// <pre>
	///      id-cmc-identityProofV2 OBJECT IDENTIFIER ::= { id-cmc 34 }
	///      identityProofV2 ::= SEQUENCE {
	///          proofAlgID       AlgorithmIdentifier,
	///          macAlgId         AlgorithmIdentifier,
	///          witness          OCTET STRING
	///      }
	/// </pre>
	/// </summary>
	public class IdentityProofV2 : ASN1Object
	{
		private readonly AlgorithmIdentifier proofAlgID;
		private readonly AlgorithmIdentifier macAlgId;
		private readonly byte[] witness;

		public IdentityProofV2(AlgorithmIdentifier proofAlgID, AlgorithmIdentifier macAlgId, byte[] witness)
		{
			this.proofAlgID = proofAlgID;
			this.macAlgId = macAlgId;
			this.witness = Arrays.clone(witness);
		}

		private IdentityProofV2(ASN1Sequence seq)
		{
			if (seq.size() != 3)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.proofAlgID = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
			this.macAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
			this.witness = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());
		}

		public static IdentityProofV2 getInstance(object o)
		{
			if (o is IdentityProofV2)
			{
				return (IdentityProofV2)o;
			}

			if (o != null)
			{
				return new IdentityProofV2(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual AlgorithmIdentifier getProofAlgID()
		{
			return proofAlgID;
		}

		public virtual AlgorithmIdentifier getMacAlgId()
		{
			return macAlgId;
		}

		public virtual byte[] getWitness()
		{
			return Arrays.clone(witness);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(proofAlgID);
			v.add(macAlgId);
			v.add(new DEROctetString(getWitness()));

			return new DERSequence(v);
		}
	}

}