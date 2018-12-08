namespace org.bouncycastle.crypto.generators
{

	/// <summary>
	/// KDF1 generator for derived keys and ivs as defined by IEEE P1363a/ISO 18033
	/// <br>
	/// This implementation is based on ISO 18033/IEEE P1363a.
	/// </summary>
	public class KDF1BytesGenerator : BaseKDFBytesGenerator
	{
		/// <summary>
		/// Construct a KDF1 byte generator.
		/// <para>
		/// </para>
		/// </summary>
		/// <param name="digest"> the digest to be used as the source of derived keys. </param>
		public KDF1BytesGenerator(Digest digest) : base(0, digest)
		{
		}
	}

}