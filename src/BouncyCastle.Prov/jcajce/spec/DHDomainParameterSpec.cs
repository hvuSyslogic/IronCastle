namespace org.bouncycastle.jcajce.spec
{

	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using DHValidationParameters = org.bouncycastle.crypto.@params.DHValidationParameters;

	/// <summary>
	/// Extension class for DHParameterSpec that wraps a DHDomainParameters object and provides the q domain parameter.
	/// </summary>
	public class DHDomainParameterSpec : DHParameterSpec
	{
		private readonly BigInteger q;
		private readonly BigInteger j;
		private readonly int m;

		private DHValidationParameters validationParameters;

		/// <summary>
		/// Base constructor - use the values in an existing set of domain parameters.
		/// </summary>
		/// <param name="domainParameters"> the Diffie-Hellman domain parameters to wrap. </param>
		public DHDomainParameterSpec(DHParameters domainParameters) : this(domainParameters.getP(), domainParameters.getQ(), domainParameters.getG(), domainParameters.getJ(), domainParameters.getM(), domainParameters.getL())
		{
			this.validationParameters = domainParameters.getValidationParameters();
		}

		/// <summary>
		/// Minimal constructor for parameters able to be used to verify a public key, or use with MQV.
		/// </summary>
		/// <param name="p"> the prime p defining the Galois field. </param>
		/// <param name="g"> the generator of the multiplicative subgroup of order g. </param>
		/// <param name="q"> specifies the prime factor of p - 1 </param>
		public DHDomainParameterSpec(BigInteger p, BigInteger q, BigInteger g) : this(p, q, g, null, 0)
		{
		}

		/// <summary>
		/// Minimal constructor for parameters able to be used to verify a public key, or use with MQV, and a private value length.
		/// </summary>
		/// <param name="p"> the prime p defining the Galois field. </param>
		/// <param name="g"> the generator of the multiplicative subgroup of order g. </param>
		/// <param name="q"> specifies the prime factor of p - 1 </param>
		/// <param name="l"> the maximum bit length for the private value. </param>
		public DHDomainParameterSpec(BigInteger p, BigInteger q, BigInteger g, int l) : this(p, q, g, null, l)
		{
		}

		/// <summary>
		/// X9.42 parameters with private value length.
		/// </summary>
		/// <param name="p"> the prime p defining the Galois field. </param>
		/// <param name="g"> the generator of the multiplicative subgroup of order g. </param>
		/// <param name="q"> specifies the prime factor of p - 1 </param>
		/// <param name="j"> optionally specifies the value that satisfies the equation p = jq+1 </param>
		/// <param name="l"> the maximum bit length for the private value. </param>
		public DHDomainParameterSpec(BigInteger p, BigInteger q, BigInteger g, BigInteger j, int l) : this(p, q, g, j, 0, l)
		{
		}

		/// <summary>
		/// Base constructor - the full domain parameter set.
		/// </summary>
		/// <param name="p"> the prime p defining the Galois field. </param>
		/// <param name="g"> the generator of the multiplicative subgroup of order g. </param>
		/// <param name="q"> specifies the prime factor of p - 1 </param>
		/// <param name="j"> optionally specifies the value that satisfies the equation p = jq+1 </param>
		/// <param name="m"> the minimum bit length for the private value. </param>
		/// <param name="l"> the maximum bit length for the private value. </param>
		public DHDomainParameterSpec(BigInteger p, BigInteger q, BigInteger g, BigInteger j, int m, int l) : base(p, g, l)
		{
			this.q = q;
			this.j = j;
			this.m = m;
		}

		/// <summary>
		/// Return the Q value for the domain parameter set.
		/// </summary>
		/// <returns> the value Q. </returns>
		public virtual BigInteger getQ()
		{
			return q;
		}

		/// <summary>
		/// Return the J value for the domain parameter set if available.
		/// </summary>
		/// <returns> the value J, null otherwise. </returns>
		public virtual BigInteger getJ()
		{
			return j;
		}

		/// <summary>
		/// Return the minimum bitlength for a private value to be generated from these parameters, 0 if not set.
		/// </summary>
		/// <returns> minimum bitlength for private value. </returns>
		public virtual int getM()
		{
			return m;
		}

		/// <summary>
		/// Return the DHDomainParameters object we represent.
		/// </summary>
		/// <returns> the internal DHDomainParameters. </returns>
		public virtual DHParameters getDomainParameters()
		{
			return new DHParameters(getP(), getG(), q, m, getL(), j, validationParameters);
		}
	}

}