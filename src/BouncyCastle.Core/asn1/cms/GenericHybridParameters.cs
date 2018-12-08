using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// RFC 5990 GenericHybridParameters class.
	/// <pre>
	/// GenericHybridParameters ::= SEQUENCE {
	///    kem  KeyEncapsulationMechanism,
	///    dem  DataEncapsulationMechanism
	/// }
	/// 
	/// KeyEncapsulationMechanism ::= AlgorithmIdentifier {{KEMAlgorithms}}
	/// DataEncapsulationMechanism ::= AlgorithmIdentifier {{DEMAlgorithms}}
	/// </pre>
	/// </summary>
	public class GenericHybridParameters : ASN1Object
	{
		private readonly AlgorithmIdentifier kem;
		private readonly AlgorithmIdentifier dem;

		private GenericHybridParameters(ASN1Sequence sequence)
		{
			if (sequence.size() != 2)
			{
				throw new IllegalArgumentException("ASN.1 SEQUENCE should be of length 2");
			}

			this.kem = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
			this.dem = AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
		}

		public static GenericHybridParameters getInstance(object o)
		{
			if (o is GenericHybridParameters)
			{
				return (GenericHybridParameters)o;
			}
			else if (o != null)
			{
				return new GenericHybridParameters(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public GenericHybridParameters(AlgorithmIdentifier kem, AlgorithmIdentifier dem)
		{
			this.kem = kem;
			this.dem = dem;
		}

		public virtual AlgorithmIdentifier getDem()
		{
			return dem;
		}

		public virtual AlgorithmIdentifier getKem()
		{
			return kem;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(kem);
			v.add(dem);

			return new DERSequence(v);
		}
	}

}