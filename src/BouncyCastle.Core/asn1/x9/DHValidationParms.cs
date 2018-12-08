using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x9
{

	/// @deprecated use ValidationParams 
	public class DHValidationParms : ASN1Object
	{
		private DERBitString seed;
		private ASN1Integer pgenCounter;

		public static DHValidationParms getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static DHValidationParms getInstance(object obj)
		{
			if (obj is DHValidationParms)
			{
				return (DHValidationParms)obj;
			}
			else if (obj != null)
			{
				return new DHValidationParms(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public DHValidationParms(DERBitString seed, ASN1Integer pgenCounter)
		{
			if (seed == null)
			{
				throw new IllegalArgumentException("'seed' cannot be null");
			}
			if (pgenCounter == null)
			{
				throw new IllegalArgumentException("'pgenCounter' cannot be null");
			}

			this.seed = seed;
			this.pgenCounter = pgenCounter;
		}

		private DHValidationParms(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			this.seed = DERBitString.getInstance(seq.getObjectAt(0));
			this.pgenCounter = ASN1Integer.getInstance(seq.getObjectAt(1));
		}

		public virtual DERBitString getSeed()
		{
			return this.seed;
		}

		public virtual ASN1Integer getPgenCounter()
		{
			return this.pgenCounter;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(this.seed);
			v.add(this.pgenCounter);
			return new DERSequence(v);
		}
	}

}