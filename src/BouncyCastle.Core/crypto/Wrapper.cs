namespace org.bouncycastle.crypto
{
	public interface Wrapper
	{
		void init(bool forWrapping, CipherParameters param);

		/// <summary>
		/// Return the name of the algorithm the wrapper implements.
		/// </summary>
		/// <returns> the name of the algorithm the wrapper implements. </returns>
		string getAlgorithmName();

		byte[] wrap(byte[] @in, int inOff, int inLen);

		byte[] unwrap(byte[] @in, int inOff, int inLen);
	}

}