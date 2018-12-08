namespace org.bouncycastle.mail.smime
{


	using CMSCompressedDataParser = org.bouncycastle.cms.CMSCompressedDataParser;
	using CMSException = org.bouncycastle.cms.CMSException;

	/// <summary>
	/// Stream based containing class for an S/MIME pkcs7-mime compressed MimePart.
	/// </summary>
	public class SMIMECompressedParser : CMSCompressedDataParser
	{
		private readonly MimePart message;

		private static InputStream getInputStream(Part bodyPart, int bufferSize)
		{
			try
			{
				InputStream @in = bodyPart.getInputStream();

				if (bufferSize == 0)
				{
					return new BufferedInputStream(@in);
				}
				else
				{
					return new BufferedInputStream(@in, bufferSize);
				}
			}
			catch (IOException e)
			{
				throw new MessagingException("can't extract input stream: " + e);
			}
		}

		public SMIMECompressedParser(MimeBodyPart message) : this(message, 0)
		{
		}

		public SMIMECompressedParser(MimeMessage message) : this(message, 0)
		{
		}

		/// <summary>
		/// Create a parser from a MimeBodyPart using the passed in buffer size
		/// for reading it.
		/// </summary>
		/// <param name="message"> body part to be parsed. </param>
		/// <param name="bufferSize"> bufferSoze to be used. </param>
		public SMIMECompressedParser(MimeBodyPart message, int bufferSize) : base(getInputStream(message, bufferSize))
		{

			this.message = message;
		}

		/// <summary>
		/// Create a parser from a MimeMessage using the passed in buffer size
		/// for reading it.
		/// </summary>
		/// <param name="message"> message to be parsed. </param>
		/// <param name="bufferSize"> bufferSoze to be used. </param>
		public SMIMECompressedParser(MimeMessage message, int bufferSize) : base(getInputStream(message, bufferSize))
		{

			this.message = message;
		}

		public virtual MimePart getCompressedContent()
		{
			return message;
		}
	}

}