namespace org.bouncycastle.jce.interfaces
{

	/// <summary>
	/// interface for Elliptic Curve Private keys.
	/// </summary>
	public interface ECPrivateKey : ECKey, PrivateKey
	{
		/// <summary>
		/// return the private value D.
		/// </summary>
		BigInteger getD();
	}

}