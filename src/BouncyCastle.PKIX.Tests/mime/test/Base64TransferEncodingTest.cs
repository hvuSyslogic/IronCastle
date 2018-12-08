﻿using System;

namespace org.bouncycastle.mime.test
{

	using TestCase = junit.framework.TestCase;
	using Base64 = org.bouncycastle.util.encoders.Base64;

	public class Base64TransferEncodingTest : TestCase
	{
		private SecureRandom random = new SecureRandom();

		/// <summary>
		/// Test the decoding of some base64 arranged in lines of
		/// 64 byte base 64 encoded rows terminated CRLF.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testDecodeWellFormed()
		{
//JAVA TO C# CONVERTER NOTE: The following call to the 'RectangularArrays' helper class reproduces the rectangular array initialization that is automatic in Java:
//ORIGINAL LINE: byte[][] original = new byte[4][48];
			byte[][] original = RectangularArrays.ReturnRectangularSbyteArray(4, 48);

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			//
			// Create 4 lines of 64bytes of base64 encoded data.
			//
			for (int i = 0; i != original.Length; i++)
			{
				byte[] row = original[i];

				random.nextBytes(row);
				bos.write(Base64.encode(row));
				bos.write('\r');
				bos.write('\n');
			}

			verifyDecode(original, bos);
		}


		/// <summary>
		/// Test decode without CR only LF.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testDecodeWithoutCR()
		{
//JAVA TO C# CONVERTER NOTE: The following call to the 'RectangularArrays' helper class reproduces the rectangular array initialization that is automatic in Java:
//ORIGINAL LINE: byte[][] original = new byte[4][48];
			byte[][] original = RectangularArrays.ReturnRectangularSbyteArray(4, 48);

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			//
			// Create 4 lines of 64bytes of base64 encoded data.
			//
			for (int i = 0; i != original.Length; i++)
			{
				byte[] row = original[i];

				random.nextBytes(row);
				bos.write(Base64.encode(row));
				bos.write('\n');
			}

			verifyDecode(original, bos);
		}


		/// <summary>
		/// Test decode with long lines past the length in the spec.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testDecodeLongLines()
		{
//JAVA TO C# CONVERTER NOTE: The following call to the 'RectangularArrays' helper class reproduces the rectangular array initialization that is automatic in Java:
//ORIGINAL LINE: byte[][] original = new byte[4][765];
			byte[][] original = RectangularArrays.ReturnRectangularSbyteArray(4, 765);

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			//
			// Create 4 lines of 1023 bytes of base64 encoded data.
			//
			for (int i = 0; i != original.Length; i++)
			{
				byte[] row = original[i];
				random.nextBytes(row);
				bos.write(Base64.encode(row));
				bos.write('\n');
			}

			verifyDecode(original, bos);
		}


		/// <summary>
		/// Test decode with long lines past the length in the spec.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testExcessiveLongLine()
		{
//JAVA TO C# CONVERTER NOTE: The following call to the 'RectangularArrays' helper class reproduces the rectangular array initialization that is automatic in Java:
//ORIGINAL LINE: byte[][] original = new byte[4][766];
			byte[][] original = RectangularArrays.ReturnRectangularSbyteArray(4, 766);

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			//
			// Create 4 lines of 1023 bytes of base64 encoded data.
			//
			for (int i = 0; i != original.Length; i++)
			{
				byte[] row = original[i];

				random.nextBytes(row);
				bos.write(Base64.encode(row));
				bos.write('\n');
			}

			try
			{
				verifyDecode(original, bos);
			}
			catch (Exception ex)
			{
				TestCase.assertEquals("End of line of base64 not reached before line buffer overflow.", ex.Message);
			}
		}


		/// <summary>
		/// Test decode of empty data.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testEmpty()
		{
			// Assertions in verifyDecode()
			verifyDecode(new byte[0][], new ByteArrayOutputStream());
		}


		private void verifyDecode(byte[][] original, ByteArrayOutputStream bos)
		{
	//        MimeParserInputStream source = new MimeParserInputStream(new ByteArrayInputStream(bos.toByteArray()), 1024);
	//        Base64TransferDecoder bte = new Base64TransferDecoder(source, 1024);
	//
	//        for (byte[] row : original)
	//        {
	//            for (byte expected : row)
	//            {
	//                TestCase.assertEquals(expected & 0xFF, bte.read());
	//            }
	//        }
	//
	//        TestCase.assertEquals(-1, bte.read());

		}


		/// <summary>
		/// This test causes the final line of base64 to not be a multiple of 64.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testDecodeLengths()
		{
//JAVA TO C# CONVERTER NOTE: The following call to the 'RectangularArrays' helper class reproduces the rectangular array initialization that is automatic in Java:
//ORIGINAL LINE: byte[][] original = new byte[4][48];
			byte[][] original = RectangularArrays.ReturnRectangularSbyteArray(4, 48);
			original[original.Length - 1] = new byte[22];

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			//
			// Create 4 lines of 64bytes of base64 encoded data.
			//
			for (int i = 0; i != original.Length; i++)
			{
				byte[] row = original[i];

				random.nextBytes(row);
				bos.write(Base64.encode(row));
				bos.write('\r');
				bos.write('\n');
			}

			verifyDecode(original, bos);
		}


		/// <summary>
		/// This test causes the final line of base64 to not be a multiple of 64.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testPartialLineEnding()
		{
//JAVA TO C# CONVERTER NOTE: The following call to the 'RectangularArrays' helper class reproduces the rectangular array initialization that is automatic in Java:
//ORIGINAL LINE: byte[][] original = new byte[4][48];
			byte[][] original = RectangularArrays.ReturnRectangularSbyteArray(4, 48);
			original[original.Length - 1] = new byte[22];

			ByteArrayOutputStream bos = new ByteArrayOutputStream();

			//
			// Create 4 lines of 64bytes of base64 encoded data.
			//
			for (int i = 0; i != original.Length; i++)
			{
				byte[] row = original[i];

				random.nextBytes(row);
				bos.write(Base64.encode(row));
				bos.write('\r');
				bos.write('\n');
			}

			verifyDecode(original, bos);
		}


		public virtual void testMultilined()
		{
			string b64 = "MIAGCSqGSIb3DQEHA6CAMIACAQAxggFOMIIBSgIBADCBsjCBrDELMAkGA1UEBhMCQVQxEDAOBgNV\n" +
				"BAgTB0F1c3RyaWExDzANBgNVBAcTBlZpZW5uYTEaMBgGA1UEChMRVGlhbmkgU3Bpcml0IEdtYkgx\n" +
				"GTAXBgNVBAsTEERlbW8gRW52aXJvbm1lbnQxEDAOBgNVBAMTB1Rlc3QgQ0ExMTAvBgkqhkiG9w0B\n" +
				"CQEWIm1hc3NpbWlsaWFuby5tYXNpQHRpYW5pLXNwaXJpdC5jb20CAQkwDQYJKoZIhvcNAQEBBQAE\n" +
				"gYALxKaiVW43jHjDiJ4kC6N90lpyG0jxeJ7nynWaR4YkDiUQ/jE8cJwRX0jBQeWKRvf3Y+XhRuB3\n" +
				"B76cKxBGTgMh6pCuLoIvgBJq54kqql/xz3hO7QRvvuHnEljlw2uhd0PQqQYe8oLdu1Yqyo9+9Jsx\n" +
				"I7QX43E2H5b3nNGND24djDCABgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBD+UNge0S52HEPuFBEq\n" +
				"IEvYoIAEggHAcOET1XS7H/OZALZ0cyns3p6kxgAlblE4BvMQnAen8VlhDehp130WdDF4jC+zRjza\n" +
				"ZftPatKq/Hlhu0wuj+FZESjy2d2hR7FT8qCqGda70IyyOhloG7Ym+17E0MyYQsH38i+uC8NjcSeo\n" +
				"egggsQoidePpg/9BNFMA4j6vORFcNBvnwj71mV2icx7mUud97cXobJnrfm3hmEmYkm7wL413cibH\n" +
				"b8K3yNu/hMqJViT0GvlhQdR9hDgu5i2WhiE2UTaFu3xL2xNhzXBvhOwj/gikzFIWva4S/2JfK3M8\n" +
				"A0lYu6f1vYUF2jazi81wQFEF7qKyp7zx7X2iZjn8DDSCY73izHafF1JJijDFaHrD5245kaSJ7MKP\n" +
				"jJ/HWk9lbed0ay8f96QuvWEEKSy4xejy6w7DKxKr4icN7KDE5Nyc2ZAJxmCm50B7yHpNZfKQ38E+\n" +
				"e/bCgvAESFcnw9pRJz9mXmwazxEvCpoO/ezgmgro+59CCRKqdUeOyyLQg6d7xqUcgeY1SoDxzEre\n" +
				"i4IBlig6+HWLs+9OPMa2fuYYIVZvg7mpeM4lEfdhRssWBWwTTmrtwRbAaT7BTCtlvfqzpHrycp5O\n" +
				"zgAAAAAAAAAAAAA=";


			byte[] data = Base64.decode(b64);

	//
	//        MimeParserInputStream mpin = new MimeParserInputStream(new ByteArrayInputStream(b64.getBytes()), 1024);
	//        Base64TransferDecoder btd = new Base64TransferDecoder(mpin, 1024);
	//
	//
	//        for (int t = 0; t < data.length; t++)
	//        {
	//            TestCase.assertEquals("Position: " + t, data[t] & 0xFF, btd.read());
	//        }
	//
	//        TestCase.assertEquals(-1, btd.read());

		}

	}



}