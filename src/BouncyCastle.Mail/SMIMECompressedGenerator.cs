namespace org.bouncycastle.mail.smime
{


	using CMSCompressedDataGenerator = org.bouncycastle.cms.CMSCompressedDataGenerator;
	using CMSCompressedDataStreamGenerator = org.bouncycastle.cms.CMSCompressedDataStreamGenerator;
	using OutputCompressor = org.bouncycastle.@operator.OutputCompressor;

	/// <summary>
	/// General class for generating a pkcs7-mime compressed message.
	/// 
	/// A simple example of usage.
	/// 
	/// <pre>
	///      SMIMECompressedGenerator  fact = new SMIMECompressedGenerator();
	/// 
	///      MimeBodyPart           smime = fact.generate(content, algorithm);
	/// </pre>
	/// 
	/// <b>Note:</b> Most clients expect the MimeBodyPart to be in a MimeMultipart
	/// when it's sent.
	/// </summary>
	public class SMIMECompressedGenerator : SMIMEGenerator
	{
		public const string ZLIB = CMSCompressedDataGenerator.ZLIB;

		private const string COMPRESSED_CONTENT_TYPE = @"application/pkcs7-mime; name=""smime.p7z""; smime-type=compressed-data";

		static SMIMECompressedGenerator()
		{
			CommandMap commandMap = CommandMap.getDefaultCommandMap();

			if (commandMap is MailcapCommandMap)
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.activation.MailcapCommandMap mc = (javax.activation.MailcapCommandMap)commandMap;
				MailcapCommandMap mc = (MailcapCommandMap)commandMap;

				mc.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
				mc.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");

				AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass(mc));
			}
		}

		public class PrivilegedActionAnonymousInnerClass : PrivilegedAction
		{
			private MailcapCommandMap mc;

			public PrivilegedActionAnonymousInnerClass(MailcapCommandMap mc)
			{
				this.mc = mc;
			}

			public object run()
			{
				CommandMap.setDefaultCommandMap(mc);

				return null;
			}
		}

		/// <summary>
		/// generate an compressed object that contains an SMIME Compressed
		/// object using the given compression algorithm.
		/// </summary>
		private MimeBodyPart make(MimeBodyPart content, OutputCompressor compressor)
		{
			try
			{
				MimeBodyPart data = new MimeBodyPart();

				data.setContent(new ContentCompressor(this, content, compressor), COMPRESSED_CONTENT_TYPE);
				data.addHeader("Content-Type", COMPRESSED_CONTENT_TYPE);
				data.addHeader("Content-Disposition", @"attachment; filename=""smime.p7z""");
				data.addHeader("Content-Description", "S/MIME Compressed Message");
				data.addHeader("Content-Transfer-Encoding", encoding);

				return data;
			}
			catch (MessagingException e)
			{
				throw new SMIMEException("exception putting multi-part together.", e);
			}
		}

		/// <summary>
		/// generate an compressed object that contains an SMIME Compressed
		/// object using the given provider from the contents of the passed in
		/// message
		/// </summary>
		public virtual MimeBodyPart generate(MimeBodyPart content, OutputCompressor compressor)
		{
			return make(makeContentBodyPart(content), compressor);
		}

		/// <summary>
		/// generate an compressed object that contains an SMIME Compressed
		/// object using the given provider from the contents of the passed in
		/// message
		/// </summary>
		public virtual MimeBodyPart generate(MimeMessage message, OutputCompressor compressor)
		{
			try
			{
				message.saveChanges(); // make sure we're up to date.
			}
			catch (MessagingException e)
			{
				throw new SMIMEException("unable to save message", e);
			}

			return make(makeContentBodyPart(message), compressor);
		}

		public class ContentCompressor : SMIMEStreamingProcessor
		{
			private readonly SMIMECompressedGenerator outerInstance;

			internal readonly MimeBodyPart content;
			internal readonly OutputCompressor compressor;

			public ContentCompressor(SMIMECompressedGenerator outerInstance, MimeBodyPart content, OutputCompressor compressor)
			{
				this.outerInstance = outerInstance;
				this.content = content;
				this.compressor = compressor;
			}

			public virtual void write(OutputStream @out)
			{
				CMSCompressedDataStreamGenerator cGen = new CMSCompressedDataStreamGenerator();

				OutputStream compressed = cGen.open(@out, compressor);

				try
				{
					content.writeTo(compressed);

					compressed.close();
				}
				catch (MessagingException e)
				{
					throw new IOException(e.ToString());
				}
			}
		}
	}

}