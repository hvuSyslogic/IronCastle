namespace org.bouncycastle.mime.test
{

	using TestCase = junit.framework.TestCase;
	using Streams = org.bouncycastle.util.io.Streams;

	public class TestBoundaryLimitedInputStream : TestCase
	{
		public virtual void testBoundaryAfterCRLF()
		{
			string data = "The cat sat on the mat\r\n" +
				"then it went to sleep";


			ByteArrayInputStream bin = new ByteArrayInputStream((data + "\r\n--banana").GetBytes());

			BoundaryLimitedInputStream blin = new BoundaryLimitedInputStream(bin, "banana");

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			Streams.pipeAll(blin, bos);

			TestCase.assertEquals(data, bos.ToString());
		}

		public virtual void testBoundaryAfterCRLFTrailingLineInContent()
		{
			string data = "The cat sat on the mat\r\n" +
				"then it went to sleep\r\n";


			ByteArrayInputStream bin = new ByteArrayInputStream((data + "\r\n--banana").GetBytes());

			BoundaryLimitedInputStream blin = new BoundaryLimitedInputStream(bin, "banana");

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			Streams.pipeAll(blin, bos);

			TestCase.assertEquals(data, bos.ToString());
		}

		public virtual void testBoundaryAfterLF()
		{
			string data = "The cat sat on the mat\r\n" +
				"then it went to sleep";


			ByteArrayInputStream bin = new ByteArrayInputStream((data + "\n--banana").GetBytes());

			BoundaryLimitedInputStream blin = new BoundaryLimitedInputStream(bin, "banana");

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			Streams.pipeAll(blin, bos);

			TestCase.assertEquals(data, bos.ToString());
		}

		public virtual void testBoundaryAfterLFTrailingLine()
		{
			string data = "The cat sat on the mat\r\n" +
				"then it went to sleep\n";


			ByteArrayInputStream bin = new ByteArrayInputStream((data + "\n--banana").GetBytes());

			BoundaryLimitedInputStream blin = new BoundaryLimitedInputStream(bin,"banana");

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			Streams.pipeAll(blin, bos);

			TestCase.assertEquals(data, bos.ToString());
		}
	}

}