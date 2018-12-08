namespace org.bouncycastle.crypto
{
	/// <summary>
	/// base interface for general purpose byte derivation functions.
	/// </summary>
	public interface DerivationFunction
	{
		void init(DerivationParameters param);

		int generateBytes(byte[] @out, int outOff, int len);
	}

}