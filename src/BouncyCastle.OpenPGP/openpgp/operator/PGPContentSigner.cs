namespace org.bouncycastle.openpgp.@operator
{

	public interface PGPContentSigner
	{
		OutputStream getOutputStream();

		byte[] getSignature();

		byte[] getDigest();

		int getType();

		int getHashAlgorithm();

		int getKeyAlgorithm();

		long getKeyID();
	}

}