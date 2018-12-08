namespace org.bouncycastle.mail.smime.examples
{


	using ZlibCompressor = org.bouncycastle.cms.jcajce.ZlibCompressor;

	/// <summary>
	/// a simple example that creates a single compressed mail message using the large
	/// file model.
	/// </summary>
	public class CreateLargeCompressedMail
	{
		public static void Main(string[] args)
		{
			//
			// create the generator for creating an smime/compressed message
			//
			SMIMECompressedGenerator gen = new SMIMECompressedGenerator();

			//
			// create the base for our message
			//
			MimeBodyPart msg = new MimeBodyPart();

			msg.setDataHandler(new DataHandler(new FileDataSource(new File(args[0]))));
			msg.setHeader("Content-Type", "application/octet-stream");
			msg.setHeader("Content-Transfer-Encoding", "binary");

			MimeBodyPart mp = gen.generate(msg, new ZlibCompressor());

			//
			// Get a Session object and create the mail message
			//
			Properties props = System.getProperties();
			Session session = Session.getDefaultInstance(props, null);

			Address fromUser = new InternetAddress(@"""Eric H. Echidna""<eric@bouncycastle.org>");
			Address toUser = new InternetAddress("example@bouncycastle.org");

			MimeMessage body = new MimeMessage(session);
			body.setFrom(fromUser);
			body.setRecipient(Message.RecipientType.TO, toUser);
			body.setSubject("example compressed message");
			body.setContent(mp.getContent(), mp.getContentType());
			body.saveChanges();

			body.writeTo(new FileOutputStream("compressed.message"));
		}
	}

}