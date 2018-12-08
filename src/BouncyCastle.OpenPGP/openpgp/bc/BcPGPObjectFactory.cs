namespace org.bouncycastle.openpgp.bc
{

	using BcKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.bc.BcKeyFingerprintCalculator;

	/// <summary>
	/// <seealso cref="PGPObjectFactory"/> that uses the Bouncy Castle lightweight API to implement cryptographic
	/// primitives.
	/// </summary>
	public class BcPGPObjectFactory : PGPObjectFactory
	{
		/// <summary>
		/// Construct an object factory to read PGP objects from encoded data.
		/// </summary>
		/// <param name="encoded"> the PGP encoded data. </param>
		public BcPGPObjectFactory(byte[] encoded) : this(new ByteArrayInputStream(encoded))
		{
		}

		/// <summary>
		/// Construct an object factory to read PGP objects from a stream.
		/// </summary>
		/// <param name="in"> the stream containing PGP encoded objects. </param>
		public BcPGPObjectFactory(InputStream @in) : base(@in, new BcKeyFingerprintCalculator())
		{
		}
	}

}