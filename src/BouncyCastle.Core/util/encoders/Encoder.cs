using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.util.encoders
{

	/// <summary>
	/// Encode and decode byte arrays (typically from binary to 7-bit ASCII 
	/// encodings).
	/// </summary>
	public interface Encoder
	{
		int encode(byte[] data, int off, int length, OutputStream @out);

		int decode(byte[] data, int off, int length, OutputStream @out);

		int decode(string data, OutputStream @out);
	}

}