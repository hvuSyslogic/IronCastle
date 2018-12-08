namespace org.bouncycastle.tsp.test
{

	using TestCase = junit.framework.TestCase;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using BcDigestCalculatorProvider = org.bouncycastle.@operator.bc.BcDigestCalculatorProvider;
	using CMSTimeStampedDataParser = org.bouncycastle.tsp.cms.CMSTimeStampedDataParser;
	using Streams = org.bouncycastle.util.io.Streams;

	public class CMSTimeStampedDataParserTest : TestCase
	{

		internal CMSTimeStampedDataParser cmsTimeStampedData = null;
		internal string fileInput = "FileDaFirmare.txt.tsd.der";
		private byte[] baseData;

		public virtual void setUp()
		{
			ByteArrayOutputStream origStream = new ByteArrayOutputStream();
			InputStream @in = this.GetType().getResourceAsStream(fileInput);
			int ch;

			while ((ch = @in.read()) >= 0)
			{
				origStream.write(ch);
			}

			origStream.close();

			this.baseData = origStream.toByteArray();

			cmsTimeStampedData = new CMSTimeStampedDataParser(baseData);
		}

		public virtual void tearDown()
		{
			cmsTimeStampedData = null;
		}

		public virtual void testGetTimeStampTokens()
		{
			TimeStampToken[] tokens = cmsTimeStampedData.getTimeStampTokens();
			assertEquals(3, tokens.Length);
		}

		public virtual void testValidateAllTokens()
		{
			DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			Streams.pipeAll(cmsTimeStampedData.getContent(), bOut);

			DigestCalculator imprintCalculator = cmsTimeStampedData.getMessageImprintDigestCalculator(digestCalculatorProvider);

			Streams.pipeAll(new ByteArrayInputStream(bOut.toByteArray()), imprintCalculator.getOutputStream());

			byte[] digest = imprintCalculator.getDigest();

			TimeStampToken[] tokens = cmsTimeStampedData.getTimeStampTokens();
			for (int i = 0; i < tokens.Length; i++)
			{
				cmsTimeStampedData.validate(digestCalculatorProvider, digest, tokens[i]);
			}
		}

		public virtual void testValidate()
		{
			DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			Streams.pipeAll(cmsTimeStampedData.getContent(), bOut);

			DigestCalculator imprintCalculator = cmsTimeStampedData.getMessageImprintDigestCalculator(digestCalculatorProvider);

			Streams.pipeAll(new ByteArrayInputStream(bOut.toByteArray()), imprintCalculator.getOutputStream());

			cmsTimeStampedData.validate(digestCalculatorProvider, imprintCalculator.getDigest());
		}

	}

}