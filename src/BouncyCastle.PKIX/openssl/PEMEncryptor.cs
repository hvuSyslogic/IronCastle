namespace org.bouncycastle.openssl
{
	public interface PEMEncryptor
	{
		string getAlgorithm();

		byte[] getIV();

		byte[] encrypt(byte[] encoding);
	}

}