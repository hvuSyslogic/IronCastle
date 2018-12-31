using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.asn1.crmf
{
	
	public class EncryptedKey : ASN1Object, ASN1Choice
	{
		private EnvelopedData envelopedData;
		private EncryptedValue encryptedValue;

		public static EncryptedKey getInstance(object o)
		{
			if (o is EncryptedKey)
			{
				return (EncryptedKey)o;
			}
			else if (o is ASN1TaggedObject)
			{
				return new EncryptedKey(EnvelopedData.getInstance((ASN1TaggedObject)o, false));
			}
			else if (o is EncryptedValue)
			{
				return new EncryptedKey((EncryptedValue)o);
			}
			else
			{
				return new EncryptedKey(EncryptedValue.getInstance(o));
			}
		}

		public EncryptedKey(EnvelopedData envelopedData)
		{
			this.envelopedData = envelopedData;
		}

		public EncryptedKey(EncryptedValue encryptedValue)
		{
			this.encryptedValue = encryptedValue;
		}

		public virtual bool isEncryptedValue()
		{
			return encryptedValue != null;
		}

		public virtual ASN1Encodable getValue()
		{
			if (encryptedValue != null)
			{
				return encryptedValue;
			}

			return envelopedData;
		}

		/// <summary>
		/// <pre>
		///    EncryptedKey ::= CHOICE {
		///        encryptedValue        EncryptedValue, -- deprecated
		///        envelopedData     [0] EnvelopedData }
		///        -- The encrypted private key MUST be placed in the envelopedData
		///        -- encryptedContentInfo encryptedContent OCTET STRING.
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			if (encryptedValue != null)
			{
				return encryptedValue.toASN1Primitive();
			}

			return new DERTaggedObject(false, 0, envelopedData);
		}
	}

}