namespace org.bouncycastle.crypto.tls
{

	public interface TlsCipher
	{
		int getPlaintextLimit(int ciphertextLimit);

		byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len);

		byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len);
	}

}