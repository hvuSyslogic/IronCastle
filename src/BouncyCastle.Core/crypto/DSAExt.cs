using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto
{

	/// <summary>
	/// An "extended" interface for classes implementing DSA-style algorithms, that provides access to
	/// the group order.
	/// </summary>
	public interface DSAExt : DSA
	{
		/// <summary>
		/// Get the order of the group that the r, s values in signatures belong to.
		/// </summary>
		BigInteger getOrder();
	}

}