using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.agreement.srp
{

	
	/// <summary>
	/// Implements the server side SRP-6a protocol. Note that this class is stateful, and therefore NOT threadsafe.
	/// This implementation of SRP is based on the optimized message sequence put forth by Thomas Wu in the paper
	/// "SRP-6: Improvements and Refinements to the Secure Remote Password Protocol, 2002"
	/// </summary>
	public class SRP6Server
	{
		protected internal BigInteger N;
		protected internal BigInteger g;
		protected internal BigInteger v;

		protected internal SecureRandom random;
		protected internal Digest digest;

		protected internal BigInteger A;

		protected internal BigInteger b;
		protected internal BigInteger B;

		protected internal BigInteger u;
		protected internal BigInteger S;
		protected internal BigInteger M1;
		protected internal BigInteger M2;
		protected internal BigInteger Key;

		public SRP6Server()
		{
		}

		/// <summary>
		/// Initialises the server to accept a new client authentication attempt </summary>
		/// <param name="N"> The safe prime associated with the client's verifier </param>
		/// <param name="g"> The group parameter associated with the client's verifier </param>
		/// <param name="v"> The client's verifier </param>
		/// <param name="digest"> The digest algorithm associated with the client's verifier </param>
		/// <param name="random"> For key generation </param>
		public virtual void init(BigInteger N, BigInteger g, BigInteger v, Digest digest, SecureRandom random)
		{
			this.N = N;
			this.g = g;
			this.v = v;

			this.random = random;
			this.digest = digest;
		}

		public virtual void init(SRP6GroupParameters group, BigInteger v, Digest digest, SecureRandom random)
		{
			init(group.getN(), group.getG(), v, digest, random);
		}

		/// <summary>
		/// Generates the server's credentials that are to be sent to the client. </summary>
		/// <returns> The server's public value to the client </returns>
		public virtual BigInteger generateServerCredentials()
		{
			BigInteger k = SRP6Util.calculateK(digest, N, g);
			this.b = selectPrivateValue();
			this.B = k.multiply(v).mod(N).add(g.modPow(b, N)).mod(N);

			return B;
		}

		/// <summary>
		/// Processes the client's credentials. If valid the shared secret is generated and returned. </summary>
		/// <param name="clientA"> The client's credentials </param>
		/// <returns> A shared secret BigInteger </returns>
		/// <exception cref="CryptoException"> If client's credentials are invalid </exception>
		public virtual BigInteger calculateSecret(BigInteger clientA)
		{
			this.A = SRP6Util.validatePublicValue(N, clientA);
			this.u = SRP6Util.calculateU(digest, N, A, B);
			this.S = calculateS();

			return S;
		}

		public virtual BigInteger selectPrivateValue()
		{
			return SRP6Util.generatePrivateValue(digest, N, g, random);
		}

		private BigInteger calculateS()
		{
			return v.modPow(u, N).multiply(A).mod(N).modPow(b, N);
		}

		/// <summary>
		/// Authenticates the received client evidence message M1 and saves it only if correct.
		/// To be called after calculating the secret S. </summary>
		/// <param name="clientM1"> the client side generated evidence message </param>
		/// <returns> A boolean indicating if the client message M1 was the expected one. </returns>
		/// <exception cref="CryptoException">  </exception>
		public virtual bool verifyClientEvidenceMessage(BigInteger clientM1)
		{
			// Verify pre-requirements
			if (this.A == null || this.B == null || this.S == null)
			{
				throw new CryptoException("Impossible to compute and verify M1: " + "some data are missing from the previous operations (A,B,S)");
			}

			// Compute the own client evidence message 'M1'
			BigInteger computedM1 = SRP6Util.calculateM1(digest, N, A, B, S);
			if (computedM1.Equals(clientM1))
			{
				this.M1 = clientM1;
				return true;
			}
			return false;
		}

		/// <summary>
		/// Computes the server evidence message M2 using the previously verified values.
		/// To be called after successfully verifying the client evidence message M1. </summary>
		/// <returns> M2: the server side generated evidence message </returns>
		/// <exception cref="CryptoException"> </exception>
		public virtual BigInteger calculateServerEvidenceMessage()
		{
			// Verify pre-requirements
			if (this.A == null || this.M1 == null || this.S == null)
			{
				throw new CryptoException("Impossible to compute M2: " + "some data are missing from the previous operations (A,M1,S)");
			}

			// Compute the server evidence message 'M2'
			this.M2 = SRP6Util.calculateM2(digest, N, A, M1, S);
			return M2;
		}

		/// <summary>
		/// Computes the final session key as a result of the SRP successful mutual authentication
		/// To be called after calculating the server evidence message M2. </summary>
		/// <returns> Key: the mutual authenticated symmetric session key </returns>
		/// <exception cref="CryptoException"> </exception>
		public virtual BigInteger calculateSessionKey()
		{
			// Verify pre-requirements
			if (this.S == null || this.M1 == null || this.M2 == null)
			{
				throw new CryptoException("Impossible to compute Key: " + "some data are missing from the previous operations (S,M1,M2)");
			}
			this.Key = SRP6Util.calculateKey(digest, N, S);
			return Key;
		}
	}

}