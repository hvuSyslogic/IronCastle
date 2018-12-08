namespace org.bouncycastle.crypto.generators
{

	/// <summary>
	/// KDF2 generator for derived keys and ivs as defined by IEEE P1363a/ISO 18033
	/// <br>
	/// This implementation is based on IEEE P1363/ISO 18033.
	/// </summary>
	public class KDF2BytesGenerator : BaseKDFBytesGenerator
	{
		/// <summary>
		/// Construct a KDF2 bytes generator. Generates key material
		/// according to IEEE P1363 or ISO 18033 depending on the initialisation.
		/// <para>
		/// </para>
		/// </summary>
		/// <param name="digest"> the digest to be used as the source of derived keys. </param>
		public KDF2BytesGenerator(Digest digest) : base(1, digest)
		{
		}
	}

}