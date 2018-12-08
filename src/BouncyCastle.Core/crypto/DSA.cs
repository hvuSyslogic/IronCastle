using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto
{

	/// <summary>
	/// interface for classes implementing algorithms modeled similar to the Digital Signature Alorithm.
	/// </summary>
	public interface DSA
	{
		/// <summary>
		/// initialise the signer for signature generation or signature
		/// verification.
		/// </summary>
		/// <param name="forSigning"> true if we are generating a signature, false
		/// otherwise. </param>
		/// <param name="param"> key parameters for signature generation. </param>
		void init(bool forSigning, CipherParameters param);

		/// <summary>
		/// sign the passed in message (usually the output of a hash function).
		/// </summary>
		/// <param name="message"> the message to be signed. </param>
		/// <returns> two big integers representing the r and s values respectively. </returns>
		BigInteger[] generateSignature(byte[] message);

		/// <summary>
		/// verify the message message against the signature values r and s.
		/// </summary>
		/// <param name="message"> the message that was supposed to have been signed. </param>
		/// <param name="r"> the r signature value. </param>
		/// <param name="s"> the s signature value. </param>
		bool verifySignature(byte[] message, BigInteger r, BigInteger s);
	}

}