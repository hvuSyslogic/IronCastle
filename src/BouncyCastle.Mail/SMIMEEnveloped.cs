namespace org.bouncycastle.mail.smime
{


	using CMSEnvelopedData = org.bouncycastle.cms.CMSEnvelopedData;
	using CMSException = org.bouncycastle.cms.CMSException;

	/// <summary>
	/// containing class for an S/MIME pkcs7-mime encrypted MimePart.
	/// </summary>
	public class SMIMEEnveloped : CMSEnvelopedData
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

		public SMIMEEnveloped(MimeBodyPart message) : base(getInputStream(message))
		{

			this.message = message;
		}

		public SMIMEEnveloped(MimeMessage message) : base(getInputStream(message))
		{

			this.message = message;
		}

		public virtual MimePart getEncryptedContent()
		{
			return message;
		}
	}

}