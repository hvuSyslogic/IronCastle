using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.pkcs
{
	
	public class KeyDerivationFunc : ASN1Object
	{
		private AlgorithmIdentifier algId;

		public KeyDerivationFunc(ASN1ObjectIdentifier objectId, ASN1Encodable parameters)
		{
			this.algId = new AlgorithmIdentifier(objectId, parameters);
		}

		private KeyDerivationFunc(ASN1Sequence seq)
		{
			this.algId = AlgorithmIdentifier.getInstance(seq);
		}

		public static KeyDerivationFunc getInstance(object obj)
		{
			if (obj is KeyDerivationFunc)
			{
				return (KeyDerivationFunc)obj;
			}
			else if (obj != null)
			{
				return new KeyDerivationFunc(ASN1Sequence.getInstance(obj));
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