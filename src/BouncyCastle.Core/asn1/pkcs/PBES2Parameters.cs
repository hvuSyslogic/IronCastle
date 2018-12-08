using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.pkcs
{


	public class PBES2Parameters : ASN1Object, PKCSObjectIdentifiers
	{
		private KeyDerivationFunc func;
		private EncryptionScheme scheme;

		public static PBES2Parameters getInstance(object obj)
		{
			if (obj is PBES2Parameters)
			{
				return (PBES2Parameters)obj;
			}
			if (obj != null)
			{
				return new PBES2Parameters(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public PBES2Parameters(KeyDerivationFunc keyDevFunc, EncryptionScheme encScheme)
		{
			this.func = keyDevFunc;
			this.scheme = encScheme;
		}

		private PBES2Parameters(ASN1Sequence obj)
		{
			Enumeration e = obj.getObjects();
			ASN1Sequence funcSeq = ASN1Sequence.getInstance(((ASN1Encodable)e.nextElement()).toASN1Primitive());

			if (funcSeq.getObjectAt(0).Equals(PKCSObjectIdentifiers_Fields.id_PBKDF2))
			{
				func = new KeyDerivationFunc(PKCSObjectIdentifiers_Fields.id_PBKDF2, PBKDF2Params.getInstance(funcSeq.getObjectAt(1)));
			}
			else
			{
				func = KeyDerivationFunc.getInstance(funcSeq);
			}

			scheme = EncryptionScheme.getInstance(e.nextElement());
		}

		public virtual KeyDerivationFunc getKeyDerivationFunc()
		{
			return func;
		}

		public virtual EncryptionScheme getEncryptionScheme()
		{
			return scheme;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(func);
			v.add(scheme);

			return new DERSequence(v);
		}
	}

}