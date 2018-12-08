using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x9
{


	/// <summary>
	/// Diffie-Hellman domain validation parameters.
	/// <pre>
	/// ValidationParams ::= SEQUENCE {
	///    seed         BIT STRING,
	///    pgenCounter  INTEGER
	/// }
	/// </pre>
	/// </summary>
	public class ValidationParams : ASN1Object
	{
		private DERBitString seed;
		private ASN1Integer pgenCounter;

		public static ValidationParams getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static ValidationParams getInstance(object obj)
		{
			if (obj is ValidationParams)
			{
				return (ValidationParams)obj;
			}
			else if (obj != null)
			{
				return new ValidationParams(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public ValidationParams(byte[] seed, int pgenCounter)
		{
			if (seed == null)
			{
				throw new IllegalArgumentException("'seed' cannot be null");
			}

			this.seed = new DERBitString(seed);
			this.pgenCounter = new ASN1Integer(pgenCounter);
		}

		public ValidationParams(DERBitString seed, ASN1Integer pgenCounter)
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

		private ValidationParams(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			this.seed = DERBitString.getInstance(seq.getObjectAt(0));
			this.pgenCounter = ASN1Integer.getInstance(seq.getObjectAt(1));
		}

		public virtual byte[] getSeed()
		{
			return this.seed.getBytes();
		}

		public virtual BigInteger getPgenCounter()
		{
			return this.pgenCounter.getPositiveValue();
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