using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto
{

	/// <summary>
	/// The basic interface that basic Diffie-Hellman implementations
	/// conforms to.
	/// </summary>
	public interface BasicAgreement
	{
		/// <summary>
		/// initialise the agreement engine.
		/// </summary>
		void init(CipherParameters param);

		/// <summary>
		/// return the field size for the agreement algorithm in bytes.
		/// </summary>
		int getFieldSize();

		/// <summary>
		/// given a public key from a given party calculate the next
		/// message in the agreement sequence. 
		/// </summary>
		BigInteger calculateAgreement(CipherParameters pubKey);
	}

}