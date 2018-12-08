namespace org.bouncycastle.bcpg
{
	/// <summary>
	/// Basic tags for compression algorithms
	/// </summary>
	public interface CompressionAlgorithmTags
	{
		/// <summary>
		/// No compression. </summary>

		/// <summary>
		/// ZIP (RFC 1951) compression. Unwrapped DEFLATE. </summary>

		/// <summary>
		/// ZLIB (RFC 1950) compression. DEFLATE with a wrapper for better error detection. </summary>

		/// <summary>
		/// BZIP2 compression. Better compression than ZIP but much slower to compress and decompress. </summary>
	}

	public static class CompressionAlgorithmTags_Fields
	{
		public const int UNCOMPRESSED = 0;
		public const int ZIP = 1;
		public const int ZLIB = 2;
		public const int BZIP2 = 3;
	}

}