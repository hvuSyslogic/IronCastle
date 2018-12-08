namespace org.bouncycastle.asn1.eac
{

	public abstract class PublicKeyDataObject : ASN1Object
	{
		public static PublicKeyDataObject getInstance(object obj)
		{
			if (obj is PublicKeyDataObject)
			{
				return (PublicKeyDataObject)obj;
			}
			if (obj != null)
			{
				ASN1Sequence seq = ASN1Sequence.getInstance(obj);
				ASN1ObjectIdentifier usage = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

				if (usage.on(EACObjectIdentifiers_Fields.id_TA_ECDSA))
				{
					return new ECDSAPublicKey(seq);
				}
				else
				{
					return new RSAPublicKey(seq);
				}
			}

			return null;
		}

		public abstract ASN1ObjectIdentifier getUsage();
	}

}