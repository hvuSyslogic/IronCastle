using System;

namespace org.bouncycastle.mime.test
{

	using TestCase = junit.framework.TestCase;
	using QuotedPrintableInputStream = org.bouncycastle.mime.encoding.QuotedPrintableInputStream;
	using Strings = org.bouncycastle.util.Strings;
	using Streams = org.bouncycastle.util.io.Streams;

	public class QuotedPrintableTest : TestCase
	{
		public virtual void testQuotedPrintable()
		{
			string qp = "J'interdis aux marchands de vanter trop leur marchandises. Car ils se font =\n" +
				"vite p=C3=A9dagogues et t'enseignent comme but ce qui n'est par essence qu'=\n" +
				"un moyen, et te trompant ainsi sur la route =C3=A0 suivre les voil=C3=A0 bi=\n" +
				"ent=C3=B4t qui te d=C3=A9gradent, car si leur musique est vulgaire ils te f=\n" +
				"abriquent pour te la vendre une =C3=A2me vulgaire."; // From wikipedia.

			QuotedPrintableInputStream qpd = new QuotedPrintableInputStream(new ByteArrayInputStream(Strings.toByteArray(qp)));

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			Streams.pipeAll(qpd, bos);

			TestCase.assertEquals("J'interdis aux marchands de vanter trop leur marchandises. Car ils se font vite pédagogues et t'enseignent comme but ce qui n'est par essence qu'un moyen, et te trompant ainsi sur la route à suivre les voilà bientôt qui te dégradent, car si leur musique est vulgaire ils te fabriquent pour te la vendre une âme vulgaire.", bos.ToString());
		}

		public virtual void testCRLFHandling()
		{
			// Some client use CR others use CRLF.

			string qp = "The cat sat =\r\non the mat";
			string expected = "The cat sat on the mat";

			QuotedPrintableInputStream qpd = new QuotedPrintableInputStream(new ByteArrayInputStream(Strings.toByteArray(qp)));

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			Streams.pipeAll(qpd, bos);


			TestCase.assertEquals(expected, bos.ToString());

		}

		public virtual void testLFHandling()
		{

			// Some client use CRLF others just use LF.

			string qp = "The cat sat =\non the mat";
			string expected = "The cat sat on the mat";

			QuotedPrintableInputStream qpd = new QuotedPrintableInputStream(new ByteArrayInputStream(Strings.toByteArray(qp)));

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			Streams.pipeAll(qpd, bos);

			TestCase.assertEquals(expected, bos.ToString());
		}

		/// <summary>
		/// No character after '='.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testInvalid_1()
		{

			// Some client use CRLF others just use LF.

			string qp = "The cat sat =";


			QuotedPrintableInputStream qpd = new QuotedPrintableInputStream(new ByteArrayInputStream(Strings.toByteArray(qp)));

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			try
			{
				Streams.pipeAll(qpd, bos);
				TestCase.fail("Must fail!");
			}
			catch (Exception ioex)
			{
				TestCase.assertEquals("Quoted '=' at end of stream", ioex.Message);
			}
		}

		/// <summary>
		/// Not hex digit on first character.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testInvalid_2()
		{

			// Some client use CRLF others just use LF.

			string qp = "The cat sat =Z";

			QuotedPrintableInputStream qpd = new QuotedPrintableInputStream(new ByteArrayInputStream(Strings.toByteArray(qp)));
			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			try
			{
				Streams.pipeAll(qpd, bos);
				TestCase.fail("Must fail!");
			}
			catch (Exception ioex)
			{
				TestCase.assertEquals("Expecting '0123456789ABCDEF after quote that was not immediately followed by LF or CRLF", ioex.Message);
			}
		}

		/// <summary>
		/// Not hex digit on second character.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testInvalid_3()
		{

			// Some client use CRLF others just use LF.

			string qp = "The cat sat =AZ";

			QuotedPrintableInputStream qpd = new QuotedPrintableInputStream(new ByteArrayInputStream(Strings.toByteArray(qp)));

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			try
			{
				Streams.pipeAll(qpd, bos);
				TestCase.fail("Must fail!");
			}
			catch (Exception ioex)
			{
				TestCase.assertEquals("Expecting second '0123456789ABCDEF after quote that was not immediately followed by LF or CRLF", ioex.Message);
			}
		}
	}

}