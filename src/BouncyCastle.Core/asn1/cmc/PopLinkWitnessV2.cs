using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// <pre>
	///      id-cmc-popLinkWitnessV2 OBJECT IDENTIFIER ::= { id-cmc 33 }
	///      PopLinkWitnessV2 ::= SEQUENCE {
	///           keyGenAlgorithm   AlgorithmIdentifier,
	///           macAlgorithm      AlgorithmIdentifier,
	///           witness           OCTET STRING
	///      }
	/// </pre>
	/// </summary>
	public class PopLinkWitnessV2 : ASN1Object
	{
		private readonly AlgorithmIdentifier keyGenAlgorithm;
		private readonly AlgorithmIdentifier macAlgorithm;
		private readonly byte[] witness;

		public PopLinkWitnessV2(AlgorithmIdentifier keyGenAlgorithm, AlgorithmIdentifier macAlgorithm, byte[] witness)
		{
			this.keyGenAlgorithm = keyGenAlgorithm;
			this.macAlgorithm = macAlgorithm;
			this.witness = Arrays.clone(witness);
		}

		private PopLinkWitnessV2(ASN1Sequence seq)
		{
			if (seq.size() != 3)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.keyGenAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
			this.macAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
			this.witness = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());
		}

		public static PopLinkWitnessV2 getInstance(object o)
		{
			if (o is PopLinkWitnessV2)
			{
				return (PopLinkWitnessV2)o;
			}

			if (o != null)
			{
				return new PopLinkWitnessV2(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual AlgorithmIdentifier getKeyGenAlgorithm()
		{
			return keyGenAlgorithm;
		}

		public virtual AlgorithmIdentifier getMacAlgorithm()
		{
			return macAlgorithm;
		}

		public virtual byte[] getWitness()
		{
			return Arrays.clone(witness);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(keyGenAlgorithm);
			v.add(macAlgorithm);
			v.add(new DEROctetString(getWitness()));

			return new DERSequence(v);
		}
	}

}