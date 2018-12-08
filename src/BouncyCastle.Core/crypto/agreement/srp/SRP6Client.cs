using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.agreement.srp
{

	using SRP6GroupParameters = org.bouncycastle.crypto.@params.SRP6GroupParameters;

	/// <summary>
	/// Implements the client side SRP-6a protocol. Note that this class is stateful, and therefore NOT threadsafe.
	/// This implementation of SRP is based on the optimized message sequence put forth by Thomas Wu in the paper
	/// "SRP-6: Improvements and Refinements to the Secure Remote Password Protocol, 2002"
	/// </summary>
	public class SRP6Client
	{
		protected internal BigInteger N;
		protected internal BigInteger g;

		protected internal BigInteger a;
		protected internal BigInteger A;

		protected internal BigInteger B;

		protected internal BigInteger x;
		protected internal BigInteger u;
		protected internal BigInteger S;

		protected internal BigInteger M1;
		protected internal BigInteger M2;
		protected internal BigInteger Key;

		protected internal Digest digest;
		protected internal SecureRandom random;

		public SRP6Client()
		{
		}

		/// <summary>
		/// Initialises the client to begin new authentication attempt </summary>
		/// <param name="N"> The safe prime associated with the client's verifier </param>
		/// <param name="g"> The group parameter associated with the client's verifier </param>
		/// <param name="digest"> The digest algorithm associated with the client's verifier </param>
		/// <param name="random"> For key generation </param>
		public virtual void init(BigInteger N, BigInteger g, Digest digest, SecureRandom random)
		{
			this.N = N;
			this.g = g;
			this.digest = digest;
			this.random = random;
		}

		public virtual void init(SRP6GroupParameters group, Digest digest, SecureRandom random)
		{
			init(group.getN(), group.getG(), digest, random);
		}

		/// <summary>
		/// Generates client's credentials given the client's salt, identity and password </summary>
		/// <param name="salt"> The salt used in the client's verifier. </param>
		/// <param name="identity"> The user's identity (eg. username) </param>
		/// <param name="password"> The user's password </param>
		/// <returns> Client's public value to send to server </returns>
		public virtual BigInteger generateClientCredentials(byte[] salt, byte[] identity, byte[] password)
		{
			this.x = SRP6Util.calculateX(digest, N, salt, identity, password);
			this.a = selectPrivateValue();
			this.A = g.modPow(a, N);

			return A;
		}

		/// <summary>
		/// Generates the secret S given the server's credentials </summary>
		/// <param name="serverB"> The server's credentials </param>
		/// <returns> Client's verification message for the server </returns>
		/// <exception cref="CryptoException"> If server's credentials are invalid </exception>
		public virtual BigInteger calculateSecret(BigInteger serverB)
		{
			this.B = SRP6Util.validatePublicValue(N, serverB);
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
			BigInteger k = SRP6Util.calculateK(digest, N, g);
			BigInteger exp = u.multiply(x).add(a);
			BigInteger tmp = g.modPow(x, N).multiply(k).mod(N);
			return B.subtract(tmp).mod(N).modPow(exp, N);
		}

		/// <summary>
		/// Computes the client evidence message M1 using the previously received values.
		/// To be called after calculating the secret S. </summary>
		/// <returns> M1: the client side generated evidence message </returns>
		/// <exception cref="CryptoException"> </exception>
		public virtual BigInteger calculateClientEvidenceMessage()
		{
			// Verify pre-requirements
			if (this.A == null || this.B == null || this.S == null)
			{
				throw new CryptoException("Impossible to compute M1: " + "some data are missing from the previous operations (A,B,S)");
			}
			// compute the client evidence message 'M1'
			this.M1 = SRP6Util.calculateM1(digest, N, A, B, S);
			return M1;
		}

		/// <summary>
		/// Authenticates the server evidence message M2 received and saves it only if correct. </summary>
		/// <param name="serverM2"> the server side generated evidence message </param>
		/// <returns> A boolean indicating if the server message M2 was the expected one. </returns>
		/// <exception cref="CryptoException"> </exception>
		public virtual bool verifyServerEvidenceMessage(BigInteger serverM2)
		{
			// Verify pre-requirements
			if (this.A == null || this.M1 == null || this.S == null)
			{
				throw new CryptoException("Impossible to compute and verify M2: " + "some data are missing from the previous operations (A,M1,S)");
			}

			// Compute the own server evidence message 'M2'
			BigInteger computedM2 = SRP6Util.calculateM2(digest, N, A, M1, S);
			if (computedM2.Equals(serverM2))
			{
				this.M2 = serverM2;
				return true;
			}
			return false;
		}

		/// <summary>
		/// Computes the final session key as a result of the SRP successful mutual authentication
		/// To be called after verifying the server evidence message M2. </summary>
		/// <returns> Key: the mutually authenticated symmetric session key </returns>
		/// <exception cref="CryptoException"> </exception>
		public virtual BigInteger calculateSessionKey()
		{
			// Verify pre-requirements (here we enforce a previous calculation of M1 and M2)
			if (this.S == null || this.M1 == null || this.M2 == null)
			{
				throw new CryptoException("Impossible to compute Key: " + "some data are missing from the previous operations (S,M1,M2)");
			}
			this.Key = SRP6Util.calculateKey(digest, N, S);
			return Key;
		}
	}

}