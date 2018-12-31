using org.bouncycastle.asn1.cms;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.crmf
{
	
	public class POPOPrivKey : ASN1Object, ASN1Choice
	{
		public const int thisMessage = 0;
		public const int subsequentMessage = 1;
		public const int dhMAC = 2;
		public const int agreeMAC = 3;
		public const int encryptedKey = 4;

		private int tagNo;
		private ASN1Encodable obj;

		private POPOPrivKey(ASN1TaggedObject obj)
		{
			this.tagNo = obj.getTagNo();

			switch (tagNo)
			{
			case thisMessage:
				this.obj = DERBitString.getInstance(obj, false);
				break;
			case subsequentMessage:
				this.obj = SubsequentMessage.valueOf(ASN1Integer.getInstance(obj, false).getValue().intValue());
				break;
			case dhMAC:
				this.obj = DERBitString.getInstance(obj, false);
				break;
			case agreeMAC:
				this.obj = PKMACValue.getInstance(obj, false);
				break;
			case encryptedKey:
				this.obj = EnvelopedData.getInstance(obj, false);
				break;
			default:
				throw new IllegalArgumentException("unknown tag in POPOPrivKey");
			}
		}

		public static POPOPrivKey getInstance(object obj)
		{
			if (obj is POPOPrivKey)
			{
				return (POPOPrivKey)obj;
			}
			if (obj != null)
			{
				return new POPOPrivKey(ASN1TaggedObject.getInstance(obj));
			}

			return null;
		}

		public static POPOPrivKey getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1TaggedObject.getInstance(obj, @explicit));
		}

		public POPOPrivKey(PKMACValue agreeMac)
		{
			this.tagNo = agreeMAC;
			this.obj = agreeMac;
		}

		public POPOPrivKey(SubsequentMessage msg)
		{
			this.tagNo = subsequentMessage;
			this.obj = msg;
		}

		public virtual int getType()
		{
			return tagNo;
		}

		public virtual ASN1Encodable getValue()
		{
			return obj;
		}

		/// <summary>
		/// <pre>
		/// POPOPrivKey ::= CHOICE {
		///        thisMessage       [0] BIT STRING,         -- Deprecated
		///         -- possession is proven in this message (which contains the private
		///         -- key itself (encrypted for the CA))
		///        subsequentMessage [1] SubsequentMessage,
		///         -- possession will be proven in a subsequent message
		///        dhMAC             [2] BIT STRING,         -- Deprecated
		///        agreeMAC          [3] PKMACValue,
		///        encryptedKey      [4] EnvelopedData }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return new DERTaggedObject(false, tagNo, obj);
		}
	}

}