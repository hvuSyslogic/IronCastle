namespace org.bouncycastle.mime.test
{

	using TestCase = junit.framework.TestCase;
	using Strings = org.bouncycastle.util.Strings;

	public class MimeParserTest : TestCase
	{
		public virtual void testMixtureOfHeaders()
		{

			string[] parts = new string[]{"Received", "from mr11p26im-asmtp003.me.com (mr11p26im-asmtp003.me.com [17.110.86.110]) " + "by tauceti.org.au (Our Mail Server) with ESMTP (TLS) id 23294071-1879654 " + "for <megan@cryptoworkshop.com>; Fri, 29 Jun 2018 14:52:26 +1000\n", "Return-Path", " <pogobot@icloud.com>\n", "X-Verify-SMTP", " Host 17.110.86.110 sending to us was not listening\r\n"};


			string values = parts[0] + ":" + parts[1] + parts[2] + ":" + parts[3] + parts[4] + ":" + parts[5] + "\r\n";

			Headers headers = new Headers(new ByteArrayInputStream(Strings.toByteArray(values)), "7bit");

			for (int t = 0; t < parts.Length; t += 2)
			{
				TestCase.assertEquals("Part " + t, parts[t + 1].Trim(), headers.getValues(parts[t])[0]);
			}

		}

		public virtual void testEndOfHeaders()
		{
			string values = "Foo: bar\r\n\r\n";

			Headers headers = new Headers(new ByteArrayInputStream(Strings.toByteArray(values)), "7bit");

			assertEquals("bar", headers.getValues("Foo")[0]);
		}
	}

}