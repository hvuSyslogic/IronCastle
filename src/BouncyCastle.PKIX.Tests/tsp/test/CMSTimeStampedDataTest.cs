using System;

namespace org.bouncycastle.tsp.test
{

	using TestCase = junit.framework.TestCase;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using BcDigestCalculatorProvider = org.bouncycastle.@operator.bc.BcDigestCalculatorProvider;
	using CMSTimeStampedData = org.bouncycastle.tsp.cms.CMSTimeStampedData;

	public class CMSTimeStampedDataTest : TestCase
	{
		private bool InstanceFieldsInitialized = false;

		public CMSTimeStampedDataTest()
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
		}

		private void InitializeInstanceFields()
		{
			fileOutput = fileInput.Substring(0, fileInput.IndexOf(".tsd", StringComparison.Ordinal));
		}


		internal CMSTimeStampedData cmsTimeStampedData = null;
		internal string fileInput = "FileDaFirmare.txt.tsd.der";
		internal string fileOutput;
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

			cmsTimeStampedData = new CMSTimeStampedData(baseData);
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

			DigestCalculator imprintCalculator = cmsTimeStampedData.getMessageImprintDigestCalculator(digestCalculatorProvider);

			imprintCalculator.getOutputStream().write(cmsTimeStampedData.getContent());

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

			DigestCalculator imprintCalculator = cmsTimeStampedData.getMessageImprintDigestCalculator(digestCalculatorProvider);

			imprintCalculator.getOutputStream().write(cmsTimeStampedData.getContent());

			cmsTimeStampedData.validate(digestCalculatorProvider, imprintCalculator.getDigest());
		}

	}

}