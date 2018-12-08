namespace org.bouncycastle.mail.smime.examples
{


	using ZlibExpanderProvider = org.bouncycastle.cms.jcajce.ZlibExpanderProvider;
	using SharedFileInputStream = org.bouncycastle.mail.smime.util.SharedFileInputStream;

	/// <summary>
	/// a simple example that reads an oversize compressed email and writes data contained
	/// in the compressed part into a file.
	/// </summary>
	public class ReadLargeCompressedMail
	{
		public static void Main(string[] args)
		{
			//
			// Get a Session object with the default properties.
			//         
			Properties props = System.getProperties();

			Session session = Session.getDefaultInstance(props, null);

			MimeMessage msg = new MimeMessage(session, new SharedFileInputStream("compressed.message"));

			SMIMECompressedParser m = new SMIMECompressedParser(msg);
			MimeBodyPart res = SMIMEUtil.toMimeBodyPart(m.getContent(new ZlibExpanderProvider()));

			ExampleUtils.dumpContent(res, args[0]);
		}
	}

}