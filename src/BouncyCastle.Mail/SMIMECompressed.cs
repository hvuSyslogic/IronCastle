namespace org.bouncycastle.mail.smime
{


	using CMSCompressedData = org.bouncycastle.cms.CMSCompressedData;
	using CMSException = org.bouncycastle.cms.CMSException;

	/// <summary>
	/// containing class for an S/MIME pkcs7-mime MimePart.
	/// </summary>
	public class SMIMECompressed : CMSCompressedData
	{
		internal MimePart message;

		private static InputStream getInputStream(Part bodyPart)
		{
			try
			{
				return bodyPart.getInputStream();
			}
			catch (IOException e)
			{
				throw new MessagingException("can't extract input stream: " + e);
			}
		}

		public SMIMECompressed(MimeBodyPart message) : base(getInputStream(message))
		{

			this.message = message;
		}

		public SMIMECompressed(MimeMessage message) : base(getInputStream(message))
		{

			this.message = message;
		}

		public virtual MimePart getCompressedContent()
		{
			return message;
		}
	}

}