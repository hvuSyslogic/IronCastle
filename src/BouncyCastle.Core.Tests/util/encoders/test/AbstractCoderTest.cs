namespace org.bouncycastle.util.encoders.test
{

	using TestCase = junit.framework.TestCase;

	public abstract class AbstractCoderTest : TestCase
	{

		private static readonly int[] SIZES_TO_CHECK = new int[] {64, 128, 1024, 1025, 1026, 2048, 2049, 2050, 4096, 4097, 4098, 8192, 8193, 8194};

		protected internal Encoder enc;
		private Random r;

		public AbstractCoderTest(string name) : base(name)
		{
		}

		public virtual void setUp()
		{
			r = new Random();
		}

		private void checkArrayOfSize(int size)
		{
			byte[] original = new byte[size];
			r.nextBytes(original);

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			enc.encode(original, 0, original.Length, bOut);

			byte[] encoded = bOut.toByteArray();

			assertTrue(encoded.Length > original.Length);
			assertTrue(encoded.Length <= (original.Length * 2));
			checkEncoding(encoded);
			checkSimpleDecode(original, encoded);
			checkStringDecode(original, encoded);
			checkOutputStreamDecode(original, encoded);

			int offset = r.nextInt(20);
			byte[] offsetEncoded = new byte[offset + encoded.Length];
			JavaSystem.arraycopy(encoded, 0, offsetEncoded, offset, encoded.Length);
			checkOffsetDecode(original, offsetEncoded, offset, encoded.Length);

			offset = r.nextInt(20);
			byte[] offsetOriginal = new byte[offset + original.Length];
			JavaSystem.arraycopy(original, 0, offsetOriginal, offset, original.Length);
			checkOffsetEncode(original, offsetOriginal, offset, original.Length);

			byte[] encodedWithSpace = addWhitespace(encoded);
			checkSimpleDecode(original, encodedWithSpace);
			checkStringDecode(original, encodedWithSpace);
			checkOutputStreamDecode(original, encodedWithSpace);
		}

		public virtual void testEncode()
		{
			for (int i = 0; i < SIZES_TO_CHECK.Length; i++)
			{
				checkArrayOfSize(SIZES_TO_CHECK[i]);
			}
		}

		private void checkEncoding(byte[] encoded)
		{
			string encString = convertBytesToString(encoded);
			for (int i = 0; i < encString.Length; i++)
			{
				char c = encString[i];
				if (c == paddingChar())
				{
					// should only be padding at end of string
					assertTrue(i > encString.Length - 3);
					continue;
				}
				else if (isEncodedChar(c))
				{
					continue;
				}
				fail("Unexpected encoded character " + c);
			}
		}

		private void checkOutputStreamDecode(byte[] original, byte[] encoded)
		{
			string encString = convertBytesToString(encoded);
			ByteArrayOutputStream @out = new ByteArrayOutputStream();
			try
			{
				assertEquals(original.Length, enc.decode(encString, @out));
				assertTrue(Arrays.Equals(original, @out.toByteArray()));
			}
			catch (IOException)
			{
				fail("This shouldn't happen");
			}
		}

		private void checkSimpleDecode(byte[] original, byte[] encoded)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			enc.decode(encoded, 0, encoded.Length, bOut);

			assertTrue(Arrays.Equals(original, bOut.toByteArray()));
		}

		private void checkOffsetEncode(byte[] original, byte[] offsetOriginal, int off, int length)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			enc.encode(offsetOriginal, off, length, bOut);

			byte[] encoded = bOut.toByteArray();

			bOut.reset();

			enc.decode(encoded, 0, encoded.Length, bOut);

			assertTrue(Arrays.Equals(original, bOut.toByteArray()));
		}

		private void checkOffsetDecode(byte[] original, byte[] encoded, int off, int length)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			enc.decode(encoded, off, length, bOut);

			assertTrue(Arrays.Equals(original, bOut.toByteArray()));
		}

		private void checkStringDecode(byte[] original, byte[] encoded)
		{
			string encString = convertBytesToString(encoded);
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			enc.decode(encString, bOut);
			assertTrue(Arrays.Equals(original, bOut.toByteArray()));
		}

		private byte[] addWhitespace(byte[] encoded)
		{
			ByteArrayOutputStream @out = new ByteArrayOutputStream();
			addSpace(@out);
			for (int i = 0; i < encoded.Length - 5; i++)
			{
				@out.write(encoded, i, 1);
				if (r.nextInt(100) < 5)
				{
					addSpace(@out);
				}
			}
			for (int i = encoded.Length - 5; i < encoded.Length; i++)
			{
				@out.write(encoded, i, 1);
			}
			addSpace(@out);
			return @out.toByteArray();
		}

		private void addSpace(ByteArrayOutputStream @out)
		{
			do
			{
				switch (r.nextInt(3))
				{
					case 0 :
						@out.write((int) '\n');
						break;
					case 1 :
						@out.write((int) '\r');
						break;
					case 2 :
						@out.write((int) '\t');
						break;
					case 3 :
						@out.write((int) ' ');
						break;
				}
			} while (r.nextBoolean());
		}

		private string convertBytesToString(byte[] encoded)
		{
			StringBuffer b = new StringBuffer();

			for (int i = 0; i != encoded.Length; i++)
			{
				b.append((char)(encoded[i] & 0xff));
			}

			return b.ToString();
		}

		public abstract char paddingChar();

		public abstract bool isEncodedChar(char c);

	}

}