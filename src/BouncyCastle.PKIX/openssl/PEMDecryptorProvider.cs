namespace org.bouncycastle.openssl
{
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;

	public interface PEMDecryptorProvider
	{
		PEMDecryptor get(string dekAlgName);
	}

}