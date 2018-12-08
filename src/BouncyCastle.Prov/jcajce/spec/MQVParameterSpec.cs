namespace org.bouncycastle.jcajce.spec
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Parameter spec to provide MQV ephemeral keys and user keying material.
	/// </summary>
	public class MQVParameterSpec : AlgorithmParameterSpec
	{
		private readonly PublicKey ephemeralPublicKey;
		private readonly PrivateKey ephemeralPrivateKey;
		private readonly PublicKey otherPartyEphemeralKey;
		private readonly byte[] userKeyingMaterial;

		public MQVParameterSpec(PublicKey ephemeralPublicKey, PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial)
		{
			this.ephemeralPublicKey = ephemeralPublicKey;
			this.ephemeralPrivateKey = ephemeralPrivateKey;
			this.otherPartyEphemeralKey = otherPartyEphemeralKey;
			this.userKeyingMaterial = Arrays.clone(userKeyingMaterial);
		}

		public MQVParameterSpec(PublicKey ephemeralPublicKey, PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey) : this(ephemeralPublicKey, ephemeralPrivateKey, otherPartyEphemeralKey, null)
		{
		}

		public MQVParameterSpec(KeyPair ephemeralKeyPair, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial) : this(ephemeralKeyPair.getPublic(), ephemeralKeyPair.getPrivate(), otherPartyEphemeralKey, userKeyingMaterial)
		{
		}

		public MQVParameterSpec(PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial) : this(null, ephemeralPrivateKey, otherPartyEphemeralKey, userKeyingMaterial)
		{
		}

		public MQVParameterSpec(KeyPair ephemeralKeyPair, PublicKey otherPartyEphemeralKey) : this(ephemeralKeyPair.getPublic(), ephemeralKeyPair.getPrivate(), otherPartyEphemeralKey, null)
		{
		}

		public MQVParameterSpec(PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey) : this(null, ephemeralPrivateKey, otherPartyEphemeralKey, null)
		{
		}

		public virtual PrivateKey getEphemeralPrivateKey()
		{
			return ephemeralPrivateKey;
		}

		public virtual PublicKey getEphemeralPublicKey()
		{
			return ephemeralPublicKey;
		}

		public virtual PublicKey getOtherPartyEphemeralKey()
		{
			return otherPartyEphemeralKey;
		}

		public virtual byte[] getUserKeyingMaterial()
		{
			return Arrays.clone(userKeyingMaterial);
		}
	}

}