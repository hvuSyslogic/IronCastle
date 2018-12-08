namespace org.bouncycastle.crypto.tls
{
	/// <summary>
	/// RFC 4492 5.4
	/// </summary>
	public class ECCurveType
	{
		/// <summary>
		/// Indicates the elliptic curve domain parameters are conveyed verbosely, and the
		/// underlying finite field is a prime field.
		/// </summary>
		public const short explicit_prime = 1;

		/// <summary>
		/// Indicates the elliptic curve domain parameters are conveyed verbosely, and the
		/// underlying finite field is a characteristic-2 field.
		/// </summary>
		public const short explicit_char2 = 2;

		/// <summary>
		/// Indicates that a named curve is used. This option SHOULD be used when applicable.
		/// </summary>
		public const short named_curve = 3;

		/*
		 * Values 248 through 255 are reserved for private use.
		 */
	}

}