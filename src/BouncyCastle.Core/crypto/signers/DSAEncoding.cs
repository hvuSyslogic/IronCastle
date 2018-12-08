using System.IO;
using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.signers
{

	/// <summary>
	/// An interface for different encoding formats for DSA signatures.
	/// </summary>
	public interface DSAEncoding
	{
		/// <summary>
		/// Decode the (r, s) pair of a DSA signature.
		/// </summary>
		/// <param name="n"> the order of the group that r, s belong to. </param>
		/// <param name="encoding"> an encoding of the (r, s) pair of a DSA signature. </param>
		/// <returns> the (r, s) of a DSA signature, stored in an array of exactly two elements, r followed by s. </returns>
		/// <exception cref="IOException"> </exception>
		BigInteger[] decode(BigInteger n, byte[] encoding);

		/// <summary>
		/// Encode the (r, s) pair of a DSA signature.
		/// </summary>
		/// <param name="n"> the order of the group that r, s belong to. </param>
		/// <param name="r"> the r value of a DSA signature. </param>
		/// <param name="s"> the s value of a DSA signature. </param>
		/// <returns> an encoding of the DSA signature given by the provided (r, s) pair. </returns>
		/// <exception cref="IOException"> </exception>
		byte[] encode(BigInteger n, BigInteger r, BigInteger s);
	}

}