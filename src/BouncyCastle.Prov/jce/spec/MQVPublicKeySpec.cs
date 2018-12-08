namespace org.bouncycastle.jce.spec
{

	using MQVPublicKey = org.bouncycastle.jce.interfaces.MQVPublicKey;

	/// <summary>
	/// Static/ephemeral public key pair for use with ECMQV key agreement </summary>
	/// @deprecated use MQVParameterSpec 
	public class MQVPublicKeySpec : KeySpec, MQVPublicKey
	{
		private PublicKey staticKey;
		private PublicKey ephemeralKey;

		/// <param name="staticKey"> the static public key. </param>
		/// <param name="ephemeralKey"> the ephemeral public key. </param>
		public MQVPublicKeySpec(PublicKey staticKey, PublicKey ephemeralKey)
		{
			this.staticKey = staticKey;
			this.ephemeralKey = ephemeralKey;
		}

		/// <summary>
		/// return the static public key
		/// </summary>
		public virtual PublicKey getStaticKey()
		{
			return staticKey;
		}

		/// <summary>
		/// return the ephemeral public key
		/// </summary>
		public virtual PublicKey getEphemeralKey()
		{
			return ephemeralKey;
		}

		/// <summary>
		/// return "ECMQV"
		/// </summary>
		public virtual string getAlgorithm()
		{
			return "ECMQV";
		}

		/// <summary>
		/// return null
		/// </summary>
		public virtual string getFormat()
		{
			return null;
		}

		/// <summary>
		/// returns null
		/// </summary>
		public virtual byte[] getEncoded()
		{
			return null;
		}
	}

}