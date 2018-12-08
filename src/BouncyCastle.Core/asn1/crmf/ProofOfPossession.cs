using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.crmf
{

	public class ProofOfPossession : ASN1Object, ASN1Choice
	{
		public const int TYPE_RA_VERIFIED = 0;
		public const int TYPE_SIGNING_KEY = 1;
		public const int TYPE_KEY_ENCIPHERMENT = 2;
		public const int TYPE_KEY_AGREEMENT = 3;

		private int tagNo;
		private ASN1Encodable obj;

		private ProofOfPossession(ASN1TaggedObject tagged)
		{
			tagNo = tagged.getTagNo();
			switch (tagNo)
			{
			case 0:
				obj = DERNull.INSTANCE;
				break;
			case 1:
				obj = POPOSigningKey.getInstance(tagged, false);
				break;
			case 2:
			case 3:
				obj = POPOPrivKey.getInstance(tagged, true);
				break;
			default:
				throw new IllegalArgumentException("unknown tag: " + tagNo);
			}
		}

		public static ProofOfPossession getInstance(object o)
		{
			if (o == null || o is ProofOfPossession)
			{
				return (ProofOfPossession)o;
			}

			if (o is ASN1TaggedObject)
			{
				return new ProofOfPossession((ASN1TaggedObject)o);
			}

			throw new IllegalArgumentException("Invalid object: " + o.GetType().getName());
		}

		/// <summary>
		/// Creates a ProofOfPossession with type raVerified. </summary>
		public ProofOfPossession()
		{
			tagNo = TYPE_RA_VERIFIED;
			obj = DERNull.INSTANCE;
		}

		/// <summary>
		/// Creates a ProofOfPossession for a signing key. </summary>
		public ProofOfPossession(POPOSigningKey poposk)
		{
			tagNo = TYPE_SIGNING_KEY;
			obj = poposk;
		}

		/// <summary>
		/// Creates a ProofOfPossession for key encipherment or agreement. </summary>
		/// <param name="type"> one of TYPE_KEY_ENCIPHERMENT or TYPE_KEY_AGREEMENT </param>
		public ProofOfPossession(int type, POPOPrivKey privkey)
		{
			tagNo = type;
			obj = privkey;
		}

		public virtual int getType()
		{
			return tagNo;
		}

		public virtual ASN1Encodable getObject()
		{
			return obj;
		}

		/// <summary>
		/// <pre>
		/// ProofOfPossession ::= CHOICE {
		///                           raVerified        [0] NULL,
		///                           -- used if the RA has already verified that the requester is in
		///                           -- possession of the private key
		///                           signature         [1] POPOSigningKey,
		///                           keyEncipherment   [2] POPOPrivKey,
		///                           keyAgreement      [3] POPOPrivKey }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return new DERTaggedObject(false, tagNo, obj);
		}
	}

}