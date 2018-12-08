namespace org.bouncycastle.jce.interfaces
{

	/// <summary>
	/// Static/ephemeral public key pair for use with ECMQV key agreement </summary>
	/// @deprecated use MQVParameterSpec for passing the ephemeral key. 
	public interface MQVPublicKey : PublicKey
	{
		/// <summary>
		/// return the static public key.
		/// </summary>
		PublicKey getStaticKey();

		/// <summary>
		/// return the ephemeral public key.
		/// </summary>
		PublicKey getEphemeralKey();
	}

}