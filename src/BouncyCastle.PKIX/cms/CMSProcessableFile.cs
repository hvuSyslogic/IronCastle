namespace org.bouncycastle.cms
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;

	/// <summary>
	/// a holding class for a file of data to be processed.
	/// </summary>
	public class CMSProcessableFile : CMSTypedData, CMSReadable
	{
		private const int DEFAULT_BUF_SIZE = 32 * 1024;

		private readonly ASN1ObjectIdentifier type;
		private readonly File file;
		private readonly byte[] buf;

		public CMSProcessableFile(File file) : this(file, DEFAULT_BUF_SIZE)
		{
		}

		public CMSProcessableFile(File file, int bufSize) : this(org.bouncycastle.asn1.cms.CMSObjectIdentifiers_Fields.data, file, bufSize)
		{
		}

		public CMSProcessableFile(ASN1ObjectIdentifier type, File file, int bufSize)
		{
			this.type = type;
			this.file = file;
			buf = new byte[bufSize];
		}

		public virtual InputStream getInputStream()
		{
			return new BufferedInputStream(new FileInputStream(file), DEFAULT_BUF_SIZE);
		}

		public virtual void write(OutputStream zOut)
		{
			FileInputStream fIn = new FileInputStream(file);
			int len;

			while ((len = fIn.read(buf, 0, buf.Length)) > 0)
			{
				zOut.write(buf, 0, len);
			}

			fIn.close();
		}

		/// <summary>
		/// Return the file handle.
		/// </summary>
		public virtual object getContent()
		{
			return file;
		}

		public virtual ASN1ObjectIdentifier getContentType()
		{
			return type;
		}
	}

}