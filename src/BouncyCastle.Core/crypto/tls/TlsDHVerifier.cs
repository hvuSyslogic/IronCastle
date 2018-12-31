using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.tls
{
	
	/// <summary>
	/// Interface a class for verifying Diffie-Hellman parameters needs to conform to.
	/// </summary>
	public interface TlsDHVerifier
	{
		/// <summary>
		/// Check whether the given DH parameters are acceptable for use.
		/// </summary>
		/// <param name="dhParameters"> the <seealso cref="DHParameters"/> to check </param>
		/// <returns> true if (and only if) the specified parameters are acceptable </returns>
		bool accept(DHParameters dhParameters);
	}

}