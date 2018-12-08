namespace org.bouncycastle.pqc.crypto.test
{

	using TestCase = junit.framework.TestCase;
	using NTRUSigningKeyGenerationParameters = org.bouncycastle.pqc.crypto.ntru.NTRUSigningKeyGenerationParameters;

	public class NTRUSigningParametersTest : TestCase
	{

		public virtual void testLoadSave()
		{
			foreach (NTRUSigningKeyGenerationParameters @params in new NTRUSigningKeyGenerationParameters[]{NTRUSigningKeyGenerationParameters.TEST157, NTRUSigningKeyGenerationParameters.TEST157_PROD})
			{
				testLoadSave(@params);
			}
		}

		private void testLoadSave(NTRUSigningKeyGenerationParameters @params)
		{
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			@params.writeTo(os);
			ByteArrayInputStream @is = new ByteArrayInputStream(os.toByteArray());
			assertEquals(@params, new NTRUSigningKeyGenerationParameters(@is));
		}

		public virtual void testEqualsHashCode()
		{
			foreach (NTRUSigningKeyGenerationParameters @params in new NTRUSigningKeyGenerationParameters[]{NTRUSigningKeyGenerationParameters.TEST157, NTRUSigningKeyGenerationParameters.TEST157_PROD})
			{
				testEqualsHashCode(@params);
			}
		}

		private void testEqualsHashCode(NTRUSigningKeyGenerationParameters @params)
		{
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			@params.writeTo(os);
			ByteArrayInputStream @is = new ByteArrayInputStream(os.toByteArray());
			NTRUSigningKeyGenerationParameters params2 = new NTRUSigningKeyGenerationParameters(@is);

			assertEquals(@params, params2);
			assertEquals(@params.GetHashCode(), params2.GetHashCode());

			@params.N += 1;
			assertFalse(@params.Equals(params2));
			assertFalse(@params.Equals(params2));
			assertFalse(@params.GetHashCode() == params2.GetHashCode());
		}

		public virtual void testClone()
		{
			foreach (NTRUSigningKeyGenerationParameters @params in new NTRUSigningKeyGenerationParameters[]{NTRUSigningKeyGenerationParameters.TEST157, NTRUSigningKeyGenerationParameters.TEST157_PROD})
			{
				assertEquals(@params, @params.clone());
			}
		}
	}

}