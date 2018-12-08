using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.crmf
{

	public class PKIArchiveOptions : ASN1Object, ASN1Choice
	{
		public const int encryptedPrivKey = 0;
		public const int keyGenParameters = 1;
		public const int archiveRemGenPrivKey = 2;

		private ASN1Encodable value;

		public static PKIArchiveOptions getInstance(object o)
		{
			if (o == null || o is PKIArchiveOptions)
			{
				return (PKIArchiveOptions)o;
			}
			else if (o is ASN1TaggedObject)
			{
				return new PKIArchiveOptions((ASN1TaggedObject)o);
			}

			throw new IllegalArgumentException("unknown object: " + o);
		}

		private PKIArchiveOptions(ASN1TaggedObject tagged)
		{
			switch (tagged.getTagNo())
			{
			case encryptedPrivKey:
				value = EncryptedKey.getInstance(tagged.getObject());
				break;
			case keyGenParameters:
				value = ASN1OctetString.getInstance(tagged, false);
				break;
			case archiveRemGenPrivKey:
				value = ASN1Boolean.getInstance(tagged, false);
				break;
			default:
				throw new IllegalArgumentException("unknown tag number: " + tagged.getTagNo());
			}
		}

		public PKIArchiveOptions(EncryptedKey encKey)
		{
			this.value = encKey;
		}

		public PKIArchiveOptions(ASN1OctetString keyGenParameters)
		{
			this.value = keyGenParameters;
		}

		public PKIArchiveOptions(bool archiveRemGenPrivKey)
		{
			this.value = ASN1Boolean.getInstance(archiveRemGenPrivKey);
		}

		public virtual int getType()
		{
			if (value is EncryptedKey)
			{
				return encryptedPrivKey;
			}

			if (value is ASN1OctetString)
			{
				return keyGenParameters;
			}

			return archiveRemGenPrivKey;
		}

		public virtual ASN1Encodable getValue()
		{
			return value;
		}

		/// <summary>
		/// <pre>
		///  PKIArchiveOptions ::= CHOICE {
		///      encryptedPrivKey     [0] EncryptedKey,
		///      -- the actual value of the private key
		///      keyGenParameters     [1] KeyGenParameters,
		///      -- parameters which allow the private key to be re-generated
		///      archiveRemGenPrivKey [2] BOOLEAN }
		///      -- set to TRUE if sender wishes receiver to archive the private
		///      -- key of a key pair that the receiver generates in response to
		///      -- this request; set to FALSE if no archival is desired.
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			if (value is EncryptedKey)
			{
				return new DERTaggedObject(true, encryptedPrivKey, value); // choice
			}

			if (value is ASN1OctetString)
			{
				return new DERTaggedObject(false, keyGenParameters, value);
			}

			return new DERTaggedObject(false, archiveRemGenPrivKey, value);
		}
	}

}