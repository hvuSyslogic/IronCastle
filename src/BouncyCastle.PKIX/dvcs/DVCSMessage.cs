namespace org.bouncycastle.dvcs
{
	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;

	public abstract class DVCSMessage
	{
		private readonly ContentInfo contentInfo;

		public DVCSMessage(ContentInfo contentInfo)
		{
			this.contentInfo = contentInfo;
		}

		public virtual ASN1ObjectIdentifier getContentType()
		{
			return contentInfo.getContentType();
		}

		public abstract ASN1Encodable getContent();
	}

}