namespace org.bouncycastle.mail.smime.test
{


	using TestCase = junit.framework.TestCase;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using Arrays = org.bouncycastle.util.Arrays;

	public class SMIMETestUtil
	{
		public const bool DEBUG = true;

		static SMIMETestUtil()
		{
			Security.addProvider(new BouncyCastleProvider());
		}

		/*  
		 *  
		 *  MAIL
		 *  
		 */

		public static MimeBodyPart makeMimeBodyPart(string msg)
		{

			MimeBodyPart _mbp = new MimeBodyPart();
			_mbp.setText(msg);
			return _mbp;
		}

		public static MimeBodyPart makeMimeBodyPart(MimeMultipart mm)
		{

			MimeBodyPart _mbp = new MimeBodyPart();
			_mbp.setContent(mm, mm.getContentType());
			return _mbp;
		}

		public static MimeMultipart makeMimeMultipart(string msg1, string msg2)
		{

			MimeMultipart _mm = new MimeMultipart();
			_mm.addBodyPart(makeMimeBodyPart(msg1));
			_mm.addBodyPart(makeMimeBodyPart(msg2));

			return _mm;
		}

		public static void verifyMessageBytes(MimeBodyPart a, MimeBodyPart b)
		{
			ByteArrayOutputStream _baos = new ByteArrayOutputStream();
			a.writeTo(_baos);
			_baos.close();
			byte[] _msgBytes = _baos.toByteArray();
			_baos = new ByteArrayOutputStream();
			b.writeTo(_baos);
			_baos.close();
			byte[] _resBytes = _baos.toByteArray();

			TestCase.assertEquals(true, Arrays.areEqual(_msgBytes, _resBytes));
		}

		public static void verifyMessageBytes(MimeMessage a, MimeBodyPart b)
		{
			ByteArrayOutputStream _baos = new ByteArrayOutputStream();
			a.writeTo(_baos);
			_baos.close();
			byte[] _msgBytes = _baos.toByteArray();
			_baos = new ByteArrayOutputStream();
			b.writeTo(_baos);
			_baos.close();
			byte[] _resBytes = _baos.toByteArray();

			TestCase.assertEquals(true, Arrays.areEqual(_msgBytes, _resBytes));
		}
	}

}