namespace org.bouncycastle.util.encoders
{
	/// <summary>
	/// General interface for a translator.
	/// </summary>
	public interface Translator
	{
		/// <summary>
		/// size of the output block on encoding produced by getDecodedBlockSize()
		/// bytes.
		/// </summary>
		int getEncodedBlockSize();

		int encode(byte[] @in, int inOff, int length, byte[] @out, int outOff);

		/// <summary>
		/// size of the output block on decoding produced by getEncodedBlockSize()
		/// bytes.
		/// </summary>
		int getDecodedBlockSize();

		int decode(byte[] @in, int inOff, int length, byte[] @out, int outOff);
	}

}