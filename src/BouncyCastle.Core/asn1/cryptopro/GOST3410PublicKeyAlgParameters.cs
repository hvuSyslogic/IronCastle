namespace org.bouncycastle.asn1.cryptopro
{

	public class GOST3410PublicKeyAlgParameters : ASN1Object
	{
		private ASN1ObjectIdentifier publicKeyParamSet;
		private ASN1ObjectIdentifier digestParamSet;
		private ASN1ObjectIdentifier encryptionParamSet;

		public static GOST3410PublicKeyAlgParameters getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static GOST3410PublicKeyAlgParameters getInstance(object obj)
		{
			if (obj is GOST3410PublicKeyAlgParameters)
			{
				return (GOST3410PublicKeyAlgParameters)obj;
			}

			if (obj != null)
			{
				return new GOST3410PublicKeyAlgParameters(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public GOST3410PublicKeyAlgParameters(ASN1ObjectIdentifier publicKeyParamSet, ASN1ObjectIdentifier digestParamSet)
		{
			this.publicKeyParamSet = publicKeyParamSet;
			this.digestParamSet = digestParamSet;
			this.encryptionParamSet = null;
		}

		public GOST3410PublicKeyAlgParameters(ASN1ObjectIdentifier publicKeyParamSet, ASN1ObjectIdentifier digestParamSet, ASN1ObjectIdentifier encryptionParamSet)
		{
			this.publicKeyParamSet = publicKeyParamSet;
			this.digestParamSet = digestParamSet;
			this.encryptionParamSet = encryptionParamSet;
		}

		/// @deprecated use getInstance() 
		public GOST3410PublicKeyAlgParameters(ASN1Sequence seq)
		{
			this.publicKeyParamSet = (ASN1ObjectIdentifier)seq.getObjectAt(0);
			this.digestParamSet = (ASN1ObjectIdentifier)seq.getObjectAt(1);

			if (seq.size() > 2)
			{
				this.encryptionParamSet = (ASN1ObjectIdentifier)seq.getObjectAt(2);
			}
		}

		public virtual ASN1ObjectIdentifier getPublicKeyParamSet()
		{
			return publicKeyParamSet;
		}

		public virtual ASN1ObjectIdentifier getDigestParamSet()
		{
			return digestParamSet;
		}

		public virtual ASN1ObjectIdentifier getEncryptionParamSet()
		{
			return encryptionParamSet;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(publicKeyParamSet);
			v.add(digestParamSet);

			if (encryptionParamSet != null)
			{
				v.add(encryptionParamSet);
			}

			return new DERSequence(v);
		}
	}

}