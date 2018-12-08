namespace org.bouncycastle.jce.interfaces
{

	/// <summary>
	/// Static/ephemeral private key (pair) for use with ECMQV key agreement
	/// (Optionally provides the ephemeral public key) </summary>
	/// @deprecated use MQVParameterSpec for passing the ephemeral key. 
	public interface MQVPrivateKey : PrivateKey
	{
		/// <summary>
		/// return the static private key.
		/// </summary>
		PrivateKey getStaticPrivateKey();

		/// <summary>
		/// return the ephemeral private key.
		/// </summary>
		PrivateKey getEphemeralPrivateKey();

		/// <summary>
		/// return the ephemeral public key (may be null).
		/// </summary>
		PublicKey getEphemeralPublicKey();
	}

}