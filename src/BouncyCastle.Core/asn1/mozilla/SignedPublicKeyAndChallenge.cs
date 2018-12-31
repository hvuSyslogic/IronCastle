using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.mozilla
{
	
	/// <summary>
	/// <pre>
	///  SignedPublicKeyAndChallenge ::= SEQUENCE {
	///    publicKeyAndChallenge PublicKeyAndChallenge,
	///    signatureAlgorithm AlgorithmIdentifier,
	///    signature BIT STRING
	///  }
	/// 
	///  </pre>
	/// </summary>
	public class SignedPublicKeyAndChallenge : ASN1Object
	{
		private readonly PublicKeyAndChallenge pubKeyAndChal;
		private readonly ASN1Sequence pkacSeq;

		public static SignedPublicKeyAndChallenge getInstance(object obj)
		{
			if (obj is SignedPublicKeyAndChallenge)
			{
				return (SignedPublicKeyAndChallenge)obj;
			}
			else if (obj != null)
			{
				return new SignedPublicKeyAndChallenge(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private SignedPublicKeyAndChallenge(ASN1Sequence seq)
		{
			pkacSeq = seq;
			pubKeyAndChal = PublicKeyAndChallenge.getInstance(seq.getObjectAt(0));
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return pkacSeq;
		}

		public virtual PublicKeyAndChallenge getPublicKeyAndChallenge()
		{
			return pubKeyAndChal;
		}

		public virtual AlgorithmIdentifier getSignatureAlgorithm()
		{
			return AlgorithmIdentifier.getInstance(pkacSeq.getObjectAt(1));
		}

		public virtual DERBitString getSignature()
		{
			return DERBitString.getInstance(pkacSeq.getObjectAt(2));
		}
	}

}