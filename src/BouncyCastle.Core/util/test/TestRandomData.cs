using org.bouncycastle.util.encoders;

namespace org.bouncycastle.util.test
{
	
	/// <summary>
	/// A fixed secure random designed to return data for someone needing random bytes.
	/// </summary>
	public class TestRandomData : FixedSecureRandom
	{
		/// <summary>
		/// Constructor from a Hex encoding of the data.
		/// </summary>
		/// <param name="encoding"> a Hex encoding of the data to be returned. </param>
		public TestRandomData(string encoding) : base(new Source[] {new FixedSecureRandom.Data(Hex.decode(encoding))})
		{
		}

		/// <summary>
		/// Constructor from an array of bytes.
		/// </summary>
		/// <param name="encoding"> a byte array representing the data to be returned. </param>
		public TestRandomData(byte[] encoding) : base(new Source[] {new FixedSecureRandom.Data(encoding)})
		{
		}
	}

}