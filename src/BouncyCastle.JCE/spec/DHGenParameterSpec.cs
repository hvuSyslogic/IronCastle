namespace javax.crypto.spec
{

	/// <summary>
	/// This class specifies the set of parameters used for generating
	/// Diffie-Hellman (system) parameters for use in Diffie-Hellman key
	/// agreement. This is typically done by a central
	/// authority.
	/// <para>
	/// The central authority, after computing the parameters, must send this
	/// information to the parties looking to agree on a secret key.
	/// </para>
	/// </summary>
	public class DHGenParameterSpec : AlgorithmParameterSpec
	{
		private int primeSize;
		private int exponentSize;

		/// <summary>
		/// Constructs a parameter set for the generation of Diffie-Hellman
		/// (system) parameters. The constructed parameter set can be used to
		/// initialize an <a href="http://java.sun.com/products/jdk/1.2/docs/api/java.security.AlgorithmParameterGenerator.html"><code>AlgorithmParameterGenerator</code></a>
		/// object for the generation of Diffie-Hellman parameters.
		/// </summary>
		/// <param name="primeSize"> the size (in bits) of the prime modulus. </param>
		/// <param name="exponentSize"> the size (in bits) of the random exponent. </param>
		public DHGenParameterSpec(int primeSize, int exponentSize)
		{
			this.primeSize = primeSize;
			this.exponentSize = exponentSize;
		}

		/// <summary>
		/// Returns the size in bits of the prime modulus.
		/// </summary>
		/// <returns> the size in bits of the prime modulus </returns>
		public virtual int getPrimeSize()
		{
			return primeSize;
		}

		/// <summary>
		/// Returns the size in bits of the random exponent (private value).
		/// </summary>
		/// <returns> the size in bits of the random exponent (private value) </returns>
		public virtual int getExponentSize()
		{
			return exponentSize;
		}
	}

}