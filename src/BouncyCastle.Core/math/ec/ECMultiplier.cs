using BouncyCastle.Core.Port;

namespace org.bouncycastle.math.ec
{

	/// <summary>
	/// Interface for classes encapsulating a point multiplication algorithm
	/// for <code>ECPoint</code>s.
	/// </summary>
	public interface ECMultiplier
	{
		/// <summary>
		/// Multiplies the <code>ECPoint p</code> by <code>k</code>, i.e.
		/// <code>p</code> is added <code>k</code> times to itself. </summary>
		/// <param name="p"> The <code>ECPoint</code> to be multiplied. </param>
		/// <param name="k"> The factor by which <code>p</code> is multiplied. </param>
		/// <returns> <code>p</code> multiplied by <code>k</code>. </returns>
		ECPoint multiply(ECPoint p, BigInteger k);
	}

}