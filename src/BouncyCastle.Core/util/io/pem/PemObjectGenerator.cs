namespace org.bouncycastle.util.io.pem
{
	/// <summary>
	/// Base interface for generators of PEM objects.
	/// </summary>
	public interface PemObjectGenerator
	{
		/// <summary>
		/// Generate a PEM object.
		/// </summary>
		/// <returns> the generated object. </returns>
		/// <exception cref="PemGenerationException"> on failure. </exception>
		PemObject generate();
	}

}