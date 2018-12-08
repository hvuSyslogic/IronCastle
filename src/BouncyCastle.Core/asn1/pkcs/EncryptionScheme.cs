namespace org.bouncycastle.asn1.pkcs
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public class EncryptionScheme : ASN1Object
	{
		private AlgorithmIdentifier algId;

		public EncryptionScheme(ASN1ObjectIdentifier objectId)
		{
			this.algId = new AlgorithmIdentifier(objectId);
		}

		public EncryptionScheme(ASN1ObjectIdentifier objectId, ASN1Encodable parameters)
		{
			this.algId = new AlgorithmIdentifier(objectId, parameters);
		}

		private EncryptionScheme(ASN1Sequence seq)
		{
			this.algId = AlgorithmIdentifier.getInstance(seq);
		}

		public static EncryptionScheme getInstance(object obj)
		{
			if (obj is EncryptionScheme)
			{
				return (EncryptionScheme)obj;
			}
			else if (obj != null)
			{
				return new EncryptionScheme(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1ObjectIdentifier getAlgorithm()
		{
			return algId.getAlgorithm();
		}

		public virtual ASN1Encodable getParameters()
		{
			return algId.getParameters();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return algId.toASN1Primitive();
		}
	}

}