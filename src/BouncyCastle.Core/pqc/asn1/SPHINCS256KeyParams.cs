namespace org.bouncycastle.pqc.asn1
{
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1Object = org.bouncycastle.asn1.ASN1Object;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public class SPHINCS256KeyParams : ASN1Object
	{
		private readonly ASN1Integer version;
		private readonly AlgorithmIdentifier treeDigest;

		public SPHINCS256KeyParams(AlgorithmIdentifier treeDigest)
		{
			this.version = new ASN1Integer(0);
			this.treeDigest = treeDigest;
		}

		private SPHINCS256KeyParams(ASN1Sequence sequence)
		{
			this.version = ASN1Integer.getInstance(sequence.getObjectAt(0));
			this.treeDigest = AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
		}

		public static SPHINCS256KeyParams getInstance(object o)
		{
			if (o is SPHINCS256KeyParams)
			{
				return (SPHINCS256KeyParams)o;
			}
			else if (o != null)
			{
				return new SPHINCS256KeyParams(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual AlgorithmIdentifier getTreeDigest()
		{
			return treeDigest;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);
			v.add(treeDigest);

			return new DERSequence(v);
		}
	}

}