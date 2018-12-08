using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.signers
{

	/// <summary>
	/// Interface define calculators of K values for DSA/ECDSA.
	/// </summary>
	public interface DSAKCalculator
	{
		/// <summary>
		/// Return true if this calculator is deterministic, false otherwise.
		/// </summary>
		/// <returns> true if deterministic, otherwise false. </returns>
		bool isDeterministic();

		/// <summary>
		/// Non-deterministic initialiser.
		/// </summary>
		/// <param name="n"> the order of the DSA group. </param>
		/// <param name="random"> a source of randomness. </param>
		void init(BigInteger n, SecureRandom random);

		/// <summary>
		/// Deterministic initialiser.
		/// </summary>
		/// <param name="n"> the order of the DSA group. </param>
		/// <param name="d"> the DSA private value. </param>
		/// <param name="message"> the message being signed. </param>
		void init(BigInteger n, BigInteger d, byte[] message);

		/// <summary>
		/// Return the next valid value of K.
		/// </summary>
		/// <returns> a K value. </returns>
		BigInteger nextK();
	}

}