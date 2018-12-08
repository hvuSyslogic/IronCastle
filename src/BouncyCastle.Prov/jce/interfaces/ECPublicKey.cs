namespace org.bouncycastle.jce.interfaces
{

	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	/// <summary>
	/// interface for elliptic curve public keys.
	/// </summary>
	public interface ECPublicKey : ECKey, PublicKey
	{
		/// <summary>
		/// return the public point Q
		/// </summary>
		ECPoint getQ();
	}

}