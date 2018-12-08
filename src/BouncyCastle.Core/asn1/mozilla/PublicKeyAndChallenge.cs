namespace org.bouncycastle.asn1.mozilla
{
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

	/// <summary>
	/// This is designed to parse
	/// the PublicKeyAndChallenge created by the KEYGEN tag included by
	/// Mozilla based browsers.
	///  <pre>
	///  PublicKeyAndChallenge ::= SEQUENCE {
	///    spki SubjectPublicKeyInfo,
	///    challenge IA5STRING
	///  }
	/// 
	///  </pre>
	/// </summary>
	public class PublicKeyAndChallenge : ASN1Object
	{
		private ASN1Sequence pkacSeq;
		private SubjectPublicKeyInfo spki;
		private DERIA5String challenge;

		public static PublicKeyAndChallenge getInstance(object obj)
		{
			if (obj is PublicKeyAndChallenge)
			{
				return (PublicKeyAndChallenge)obj;
			}
			else if (obj != null)
			{
				return new PublicKeyAndChallenge(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private PublicKeyAndChallenge(ASN1Sequence seq)
		{
			pkacSeq = seq;
			spki = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(0));
			challenge = DERIA5String.getInstance(seq.getObjectAt(1));
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return pkacSeq;
		}

		public virtual SubjectPublicKeyInfo getSubjectPublicKeyInfo()
		{
			return spki;
		}

		public virtual DERIA5String getChallenge()
		{
			return challenge;
		}
	}

}