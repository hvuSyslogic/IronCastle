namespace org.bouncycastle.cms
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;

	/// <summary>
	/// a class representing null or absent content.
	/// </summary>
	public class CMSAbsentContent : CMSTypedData, CMSReadable
	{
		private readonly ASN1ObjectIdentifier type;

		public CMSAbsentContent() : this(org.bouncycastle.asn1.cms.CMSObjectIdentifiers_Fields.data)
		{
		}

		public CMSAbsentContent(ASN1ObjectIdentifier type)
		{
			this.type = type;
		}

		public virtual InputStream getInputStream()
		{
			return null;
		}

		public virtual void write(OutputStream zOut)
		{
			// do nothing
		}

		public virtual object getContent()
		{
			return null;
		}

		public virtual ASN1ObjectIdentifier getContentType()
		{
			return type;
		}
	}

}