namespace org.bouncycastle.jce.interfaces
{
	/// <summary>
	/// All BC elliptic curve keys implement this interface. You need to
	/// cast the key to get access to it.
	/// <para>
	/// By default BC keys produce encodings without point compression,
	/// to turn this on call setPointFormat() with "COMPRESSED".
	/// </para>
	/// </summary>
	public interface ECPointEncoder
	{
		/// <summary>
		/// Set the formatting for encoding of points. If the String "UNCOMPRESSED" is passed
		/// in point compression will not be used. If the String "COMPRESSED" is passed point
		/// compression will be used. The default is "UNCOMPRESSED".
		/// </summary>
		/// <param name="style"> the style to use. </param>
		void setPointFormat(string style);
	}

}