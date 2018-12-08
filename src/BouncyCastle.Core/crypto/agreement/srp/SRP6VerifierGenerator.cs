using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.agreement.srp
{

	using SRP6GroupParameters = org.bouncycastle.crypto.@params.SRP6GroupParameters;

	/// <summary>
	/// Generates new SRP verifier for user
	/// </summary>
	public class SRP6VerifierGenerator
	{
		protected internal BigInteger N;
		protected internal BigInteger g;
		protected internal Digest digest;

		public SRP6VerifierGenerator()
		{
		}

		/// <summary>
		/// Initialises generator to create new verifiers </summary>
		/// <param name="N"> The safe prime to use (see DHParametersGenerator) </param>
		/// <param name="g"> The group parameter to use (see DHParametersGenerator) </param>
		/// <param name="digest"> The digest to use. The same digest type will need to be used later for the actual authentication
		/// attempt. Also note that the final session key size is dependent on the chosen digest. </param>
		public virtual void init(BigInteger N, BigInteger g, Digest digest)
		{
			this.N = N;
			this.g = g;
			this.digest = digest;
		}

		public virtual void init(SRP6GroupParameters group, Digest digest)
		{
			this.N = group.getN();
			this.g = group.getG();
			this.digest = digest;
		}

		/// <summary>
		/// Creates a new SRP verifier </summary>
		/// <param name="salt"> The salt to use, generally should be large and random </param>
		/// <param name="identity"> The user's identifying information (eg. username) </param>
		/// <param name="password"> The user's password </param>
		/// <returns> A new verifier for use in future SRP authentication </returns>
		public virtual BigInteger generateVerifier(byte[] salt, byte[] identity, byte[] password)
		{
			BigInteger x = SRP6Util.calculateX(digest, N, salt, identity, password);

			return g.modPow(x, N);
		}
	}

}