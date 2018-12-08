using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.ec
{

	public interface ECPairFactorTransform : ECPairTransform
	{
		/// <summary>
		/// Return the last value used to calculated a transform.
		/// </summary>
		/// <returns> a BigInteger representing the last transform value used. </returns>
		BigInteger getTransformValue();
	}

}