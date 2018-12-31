using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.tls
{
	
	public interface TlsSRPGroupVerifier
	{
		/// <summary>
		/// Check whether the given SRP group parameters are acceptable for use.
		/// </summary>
		/// <param name="group"> the <seealso cref="SRP6GroupParameters"/> to check </param>
		/// <returns> true if (and only if) the specified group parameters are acceptable </returns>
		bool accept(SRP6GroupParameters group);
	}

}