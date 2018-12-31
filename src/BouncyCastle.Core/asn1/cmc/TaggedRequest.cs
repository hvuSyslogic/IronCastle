using System.IO;
using org.bouncycastle.asn1.crmf;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	
	/// <summary>
	/// <pre>
	///       TaggedRequest ::= CHOICE {
	///             tcr               [0] TaggedCertificationRequest,
	///             crm               [1] CertReqMsg,
	///             orm               [2] SEQUENCE {
	///             bodyPartID            BodyPartID,
	///             requestMessageType    OBJECT IDENTIFIER,
	///             requestMessageValue   ANY DEFINED BY requestMessageType
	///      }
	///  }
	/// </pre>
	/// </summary>
	public class TaggedRequest : ASN1Object, ASN1Choice
	{
		public const int TCR = 0;
		public const int CRM = 1;
		public const int ORM = 2;

		private readonly int tagNo;
		private readonly ASN1Encodable value;

		public TaggedRequest(TaggedCertificationRequest tcr)
		{
			this.tagNo = TCR;
			this.value = tcr;
		}

		public TaggedRequest(CertReqMsg crm)
		{
			this.tagNo = CRM;
			this.value = crm;
		}

		private TaggedRequest(ASN1Sequence orm)
		{
			this.tagNo = ORM;
			this.value = orm;
		}

		public static TaggedRequest getInstance(object obj)
		{
			if (obj is TaggedRequest)
			{
				return (TaggedRequest)obj;
			}

			if (obj != null)
			{
				if (obj is ASN1Encodable)
				{
					ASN1TaggedObject asn1Prim = ASN1TaggedObject.getInstance(((ASN1Encodable)obj).toASN1Primitive());

					switch (asn1Prim.getTagNo())
					{
					case 0:
						return new TaggedRequest(TaggedCertificationRequest.getInstance(asn1Prim, false));
					case 1:
						return new TaggedRequest(CertReqMsg.getInstance(asn1Prim, false));
					case 2:
						return new TaggedRequest(ASN1Sequence.getInstance(asn1Prim, false));
					default:
						throw new IllegalArgumentException("unknown tag in getInstance(): " + asn1Prim.getTagNo());
					}
				}
				if (obj is byte[])
				{
					try
					{
						return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
					}
					catch (IOException)
					{
						throw new IllegalArgumentException("unknown encoding in getInstance()");
					}
				}
				throw new IllegalArgumentException("unknown object in getInstance(): " + obj.GetType().getName());
			}

			return null;
		}

		public virtual int getTagNo()
		{
			return tagNo;
		}

		public virtual ASN1Encodable getValue()
		{
			return value;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DERTaggedObject(false, tagNo, value);
		}
	}

}