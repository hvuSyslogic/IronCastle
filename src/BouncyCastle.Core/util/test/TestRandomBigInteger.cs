namespace org.bouncycastle.util.test
{

	/// <summary>
	/// A fixed secure random designed to return data for someone needing to create a single BigInteger.
	/// </summary>
	public class TestRandomBigInteger : FixedSecureRandom
	{
		/// <summary>
		/// Constructor from a base 10 represention of a BigInteger.
		/// </summary>
		/// <param name="encoding"> a base 10 represention of a BigInteger. </param>
		public TestRandomBigInteger(string encoding) : this(encoding, 10)
		{
		}

		/// <summary>
		/// Constructor from a base radix represention of a BigInteger.
		/// </summary>
		/// <param name="encoding"> a String BigInteger of base radix. </param>
		/// <param name="radix"> the radix to use. </param>
		public TestRandomBigInteger(string encoding, int radix) : base(new FixedSecureRandom.Source[] {new FixedSecureRandom.BigInteger(BigIntegers.asUnsignedByteArray(new BouncyCastle.Core.Port.BigInteger(encoding, radix)))})
		{
		}

		/// <summary>
		/// Constructor based on a byte array.
		/// </summary>
		/// <param name="encoding"> a 2's complement representation of the BigInteger. </param>
		public TestRandomBigInteger(byte[] encoding) : base(new FixedSecureRandom.Source[] {new FixedSecureRandom.BigInteger(encoding)})
		{
		}

		/// <summary>
		/// Constructor which ensures encoding will produce a BigInteger from a request from the passed in bitLength.
		/// </summary>
		/// <param name="bitLength"> bit length for the BigInteger data request. </param>
		/// <param name="encoding"> bytes making up the encoding. </param>
		public TestRandomBigInteger(int bitLength, byte[] encoding) : base(new FixedSecureRandom.Source[] {new FixedSecureRandom.BigInteger(bitLength, encoding)})
		{
		}
	}

}