namespace org.bouncycastle.pqc.crypto.test
{

	using TestCase = junit.framework.TestCase;
	using NTRUEncryptionKeyGenerationParameters = org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyGenerationParameters;

	public class NTRUEncryptionParametersTest : TestCase
	{
		public virtual void testLoadSave()
		{
			NTRUEncryptionKeyGenerationParameters @params = NTRUEncryptionKeyGenerationParameters.EES1499EP1;
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			@params.writeTo(os);
			ByteArrayInputStream @is = new ByteArrayInputStream(os.toByteArray());
			assertEquals(@params, new NTRUEncryptionKeyGenerationParameters(@is));
		}

		public virtual void testEqualsHashCode()
		{
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			NTRUEncryptionKeyGenerationParameters.EES1499EP1.writeTo(os);
			ByteArrayInputStream @is = new ByteArrayInputStream(os.toByteArray());
			NTRUEncryptionKeyGenerationParameters @params = new NTRUEncryptionKeyGenerationParameters(@is);

			assertEquals(@params, NTRUEncryptionKeyGenerationParameters.EES1499EP1);
			assertEquals(@params.GetHashCode(), NTRUEncryptionKeyGenerationParameters.EES1499EP1.GetHashCode());

			@params.N += 1;
			assertFalse(@params.Equals(NTRUEncryptionKeyGenerationParameters.EES1499EP1));
			assertFalse(NTRUEncryptionKeyGenerationParameters.EES1499EP1.Equals(@params));
			assertFalse(@params.GetHashCode() == NTRUEncryptionKeyGenerationParameters.EES1499EP1.GetHashCode());
		}

		public virtual void testClone()
		{
			NTRUEncryptionKeyGenerationParameters @params = NTRUEncryptionKeyGenerationParameters.APR2011_439;
			assertEquals(@params, @params.clone());

			@params = NTRUEncryptionKeyGenerationParameters.APR2011_439_FAST;
			assertEquals(@params, @params.clone());
		}
	}

}