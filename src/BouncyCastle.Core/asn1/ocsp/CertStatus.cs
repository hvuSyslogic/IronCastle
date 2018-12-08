using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.ocsp
{

	public class CertStatus : ASN1Object, ASN1Choice
	{
		private int tagNo;
		private ASN1Encodable value;

		/// <summary>
		/// create a CertStatus object with a tag of zero.
		/// </summary>
		public CertStatus()
		{
			tagNo = 0;
			value = DERNull.INSTANCE;
		}

		public CertStatus(RevokedInfo info)
		{
			tagNo = 1;
			value = info;
		}

		public CertStatus(int tagNo, ASN1Encodable value)
		{
			this.tagNo = tagNo;
			this.value = value;
		}

		private CertStatus(ASN1TaggedObject choice)
		{
			this.tagNo = choice.getTagNo();

			switch (choice.getTagNo())
			{
			case 0:
				value = DERNull.INSTANCE;
				break;
			case 1:
				value = RevokedInfo.getInstance(choice, false);
				break;
			case 2:
				value = DERNull.INSTANCE;
				break;
			default:
				throw new IllegalArgumentException("Unknown tag encountered: " + choice.getTagNo());
			}
		}

		public static CertStatus getInstance(object obj)
		{
			if (obj == null || obj is CertStatus)
			{
				return (CertStatus)obj;
			}
			else if (obj is ASN1TaggedObject)
			{
				return new CertStatus((ASN1TaggedObject)obj);
			}

			throw new IllegalArgumentException("unknown object in factory: " + obj.GetType().getName());
		}

		public static CertStatus getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(obj.getObject()); // must be explicitly tagged
		}

		public virtual int getTagNo()
		{
			return tagNo;
		}

		public virtual ASN1Encodable getStatus()
		{
			return value;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		///  CertStatus ::= CHOICE {
		///                  good        [0]     IMPLICIT NULL,
		///                  revoked     [1]     IMPLICIT RevokedInfo,
		///                  unknown     [2]     IMPLICIT UnknownInfo }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return new DERTaggedObject(false, tagNo, value);
		}
	}

}