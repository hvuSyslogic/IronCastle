namespace org.bouncycastle.openpgp.@operator
{

	public interface PublicKeyDataDecryptorFactory : PGPDataDecryptorFactory
	{
		byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData);
	}

}