using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	/// <summary>
	/// <pre>
	/// id-cmc-lraPOPWitness OBJECT IDENTIFIER ::= {id-cmc 11}
	/// 
	/// LraPopWitness ::= SEQUENCE {
	///     pkiDataBodyid   BodyPartID,
	///     bodyIds         SEQUENCE OF BodyPartID
	/// }
	/// </pre>
	/// </summary>
	public class LraPopWitness : ASN1Object
	{
		private readonly BodyPartID pkiDataBodyid;
		private readonly ASN1Sequence bodyIds;

		public LraPopWitness(BodyPartID pkiDataBodyid, ASN1Sequence bodyIds)
		{
			this.pkiDataBodyid = pkiDataBodyid;
			this.bodyIds = bodyIds;
		}

		private LraPopWitness(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.pkiDataBodyid = BodyPartID.getInstance(seq.getObjectAt(0));
			this.bodyIds = ASN1Sequence.getInstance(seq.getObjectAt(1));
		}

		public static LraPopWitness getInstance(object o)
		{
			if (o is LraPopWitness)
			{
				return (LraPopWitness)o;
			}

			if (o != null)
			{
				return new LraPopWitness(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual BodyPartID getPkiDataBodyid()
		{
			return pkiDataBodyid;
		}


		public virtual BodyPartID[] getBodyIds()
		{
			BodyPartID[] rv = new BodyPartID[bodyIds.size()];

			for (int i = 0; i != bodyIds.size(); i++)
			{
				rv[i] = BodyPartID.getInstance(bodyIds.getObjectAt(i));
			}

			return rv;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(pkiDataBodyid);
			v.add(bodyIds);

			return new DERSequence(v);
		}
	}

}