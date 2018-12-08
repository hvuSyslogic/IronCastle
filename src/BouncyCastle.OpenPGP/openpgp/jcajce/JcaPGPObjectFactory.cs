namespace org.bouncycastle.openpgp.jcajce
{

	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;

	/// <summary>
	/// <seealso cref="PGPObjectFactory"/> that uses the sources cryptographic primitives from the JCA API.
	/// </summary>
	public class JcaPGPObjectFactory : PGPObjectFactory
	{
		/// <summary>
		/// Construct an object factory to read PGP objects from encoded data.
		/// </summary>
		/// <param name="encoded"> the PGP encoded data. </param>
		public JcaPGPObjectFactory(byte[] encoded) : this(new ByteArrayInputStream(encoded))
		{
		}

		/// <summary>
		/// Construct an object factory to read PGP objects from a stream.
		/// </summary>
		/// <param name="in"> the stream containing PGP encoded objects. </param>
		public JcaPGPObjectFactory(InputStream @in) : base(@in, new JcaKeyFingerprintCalculator())
		{
			// FIXME: Convert this to builder style so we can set provider?
		}
	}

}