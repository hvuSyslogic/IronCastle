namespace org.bouncycastle.cms
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// a holding class for a byte array of data to be processed.
	/// </summary>
	public class CMSProcessableByteArray : CMSTypedData, CMSReadable
	{
		private readonly ASN1ObjectIdentifier type;
		private readonly byte[] bytes;

		public CMSProcessableByteArray(byte[] bytes) : this(org.bouncycastle.asn1.cms.CMSObjectIdentifiers_Fields.data, bytes)
		{
		}

		public CMSProcessableByteArray(ASN1ObjectIdentifier type, byte[] bytes)
		{
			this.type = type;
			this.bytes = bytes;
		}

		public virtual InputStream getInputStream()
		{
			return new ByteArrayInputStream(bytes);
		}

		public virtual void write(OutputStream zOut)
		{
			zOut.write(bytes);
		}

		public virtual object getContent()
		{
			return Arrays.clone(bytes);
		}

		public virtual ASN1ObjectIdentifier getContentType()
		{
			return type;
		}
	}

}