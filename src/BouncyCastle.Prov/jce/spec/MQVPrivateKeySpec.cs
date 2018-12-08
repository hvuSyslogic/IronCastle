namespace org.bouncycastle.jce.spec
{

	using MQVPrivateKey = org.bouncycastle.jce.interfaces.MQVPrivateKey;

	/// <summary>
	/// Static/ephemeral private key (pair) for use with ECMQV key agreement
	/// (Optionally provides the ephemeral public key) </summary>
	/// @deprecated use MQVParameterSpec 
	public class MQVPrivateKeySpec : KeySpec, MQVPrivateKey
	{
		private PrivateKey staticPrivateKey;
		private PrivateKey ephemeralPrivateKey;
		private PublicKey ephemeralPublicKey;

		/// <param name="staticPrivateKey"> the static private key. </param>
		/// <param name="ephemeralPrivateKey"> the ephemeral private key. </param>
		public MQVPrivateKeySpec(PrivateKey staticPrivateKey, PrivateKey ephemeralPrivateKey) : this(staticPrivateKey, ephemeralPrivateKey, null)
		{
		}

		/// <param name="staticPrivateKey"> the static private key. </param>
		/// <param name="ephemeralPrivateKey"> the ephemeral private key. </param>
		/// <param name="ephemeralPublicKey"> the ephemeral public key (may be null). </param>
		public MQVPrivateKeySpec(PrivateKey staticPrivateKey, PrivateKey ephemeralPrivateKey, PublicKey ephemeralPublicKey)
		{
			this.staticPrivateKey = staticPrivateKey;
			this.ephemeralPrivateKey = ephemeralPrivateKey;
			this.ephemeralPublicKey = ephemeralPublicKey;
		}

		/// <summary>
		/// return the static private key
		/// </summary>
		public virtual PrivateKey getStaticPrivateKey()
		{
			return staticPrivateKey;
		}

		/// <summary>
		/// return the ephemeral private key
		/// </summary>
		public virtual PrivateKey getEphemeralPrivateKey()
		{
			return ephemeralPrivateKey;
		}

		/// <summary>
		/// return the ephemeral public key (may be null)
		/// </summary>
		public virtual PublicKey getEphemeralPublicKey()
		{
			return ephemeralPublicKey;
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