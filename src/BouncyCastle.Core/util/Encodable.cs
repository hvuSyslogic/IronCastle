using System.IO;

namespace org.bouncycastle.util
{

	/// <summary>
	/// Interface implemented by objects that can be converted into byte arrays.
	/// </summary>
	public interface Encodable
	{
		/// <summary>
		/// Return a byte array representing the implementing object.
		/// </summary>
		/// <returns> a byte array representing the encoding. </returns>
		/// <exception cref="IOException"> if an issue arises generation the encoding. </exception>
		byte[] getEncoded();
	}

}