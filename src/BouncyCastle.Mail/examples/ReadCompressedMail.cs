namespace org.bouncycastle.mail.smime.examples
{


	using ZlibExpanderProvider = org.bouncycastle.cms.jcajce.ZlibExpanderProvider;

	/// <summary>
	/// a simple example that reads a compressed email.
	/// <para>
	/// </para>
	/// </summary>
	public class ReadCompressedMail
	{
		public static void Main(string[] args)
		{
			//
			// Get a Session object with the default properties.
			//         
			Properties props = System.getProperties();

			Session session = Session.getDefaultInstance(props, null);

			MimeMessage msg = new MimeMessage(session, new FileInputStream("compressed.message"));

			SMIMECompressed m = new SMIMECompressed(msg);

			MimeBodyPart res = SMIMEUtil.toMimeBodyPart(m.getContent(new ZlibExpanderProvider()));

			JavaSystem.@out.println("Message Contents");
			JavaSystem.@out.println("----------------");
			JavaSystem.@out.println(res.getContent());
		}
	}

}