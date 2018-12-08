namespace org.bouncycastle.openpgp.@operator
{

	public interface PBEProtectionRemoverFactory
	{
		PBESecretKeyDecryptor createDecryptor(string protection);
	}

}