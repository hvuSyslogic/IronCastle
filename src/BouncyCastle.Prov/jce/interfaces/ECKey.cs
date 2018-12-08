namespace org.bouncycastle.jce.interfaces
{
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;

	/// <summary>
	/// generic interface for an Elliptic Curve Key.
	/// </summary>
	public interface ECKey
	{
		/// <summary>
		/// return a parameter specification representing the EC domain parameters
		/// for the key.
		/// </summary>
		ECParameterSpec getParameters();
	}

}