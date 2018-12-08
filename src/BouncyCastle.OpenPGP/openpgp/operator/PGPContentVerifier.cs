namespace org.bouncycastle.openpgp.@operator
{

	public interface PGPContentVerifier
	{
		OutputStream getOutputStream();

		int getHashAlgorithm();

		int getKeyAlgorithm();

		long getKeyID();

		/// <param name="expected"> expected value of the signature on the data. </param>
		/// <returns> true if the signature verifies, false otherwise </returns>
		bool verify(byte[] expected);
	}

}