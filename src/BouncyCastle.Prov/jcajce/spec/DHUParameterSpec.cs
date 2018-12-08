namespace org.bouncycastle.jcajce.spec
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Parameter spec to provide Diffie-Hellman Unified model keys and user keying material.
	/// </summary>
	public class DHUParameterSpec : AlgorithmParameterSpec
	{
		private readonly PublicKey ephemeralPublicKey;
		private readonly PrivateKey ephemeralPrivateKey;
		private readonly PublicKey otherPartyEphemeralKey;
		private readonly byte[] userKeyingMaterial;

		/// <summary>
		/// Base constructor for a Diffie-Hellman unified model.
		/// </summary>
		/// <param name="ephemeralPublicKey"> our ephemeral public key. </param>
		/// <param name="ephemeralPrivateKey"> our ephemeral private key. </param>
		/// <param name="otherPartyEphemeralKey"> the ephemeral public key sent by the other party. </param>
		/// <param name="userKeyingMaterial"> key generation material to mix with the calculated secret. </param>
		public DHUParameterSpec(PublicKey ephemeralPublicKey, PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial)
		{
			if (ephemeralPrivateKey == null)
			{
				throw new IllegalArgumentException("ephemeral private key cannot be null");
			}
			if (otherPartyEphemeralKey == null)
			{
				throw new IllegalArgumentException("other party ephemeral key cannot be null");
			}
			this.ephemeralPublicKey = ephemeralPublicKey;
			this.ephemeralPrivateKey = ephemeralPrivateKey;
			this.otherPartyEphemeralKey = otherPartyEphemeralKey;
			this.userKeyingMaterial = Arrays.clone(userKeyingMaterial);
		}

		/// <summary>
		/// Base constructor for a Diffie-Hellman unified model without user keying material.
		/// </summary>
		/// <param name="ephemeralPublicKey"> our ephemeral public key. </param>
		/// <param name="ephemeralPrivateKey"> our ephemeral private key. </param>
		/// <param name="otherPartyEphemeralKey"> the ephemeral public key sent by the other party. </param>
		public DHUParameterSpec(PublicKey ephemeralPublicKey, PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey) : this(ephemeralPublicKey, ephemeralPrivateKey, otherPartyEphemeralKey, null)
		{
		}

		/// <summary>
		/// Base constructor for a Diffie-Hellman unified model using a key pair.
		/// </summary>
		/// <param name="ephemeralKeyPair"> our ephemeral public and private key. </param>
		/// <param name="otherPartyEphemeralKey"> the ephemeral public key sent by the other party. </param>
		/// <param name="userKeyingMaterial"> key generation material to mix with the calculated secret. </param>
		public DHUParameterSpec(KeyPair ephemeralKeyPair, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial) : this(ephemeralKeyPair.getPublic(), ephemeralKeyPair.getPrivate(), otherPartyEphemeralKey, userKeyingMaterial)
		{
		}

		/// <summary>
		/// Base constructor for a Diffie-Hellman unified model - calculation of our ephemeral public key
		/// is required.
		/// </summary>
		/// <param name="ephemeralPrivateKey"> our ephemeral private key. </param>
		/// <param name="otherPartyEphemeralKey"> the ephemeral public key sent by the other party. </param>
		/// <param name="userKeyingMaterial"> key generation material to mix with the calculated secret. </param>
		public DHUParameterSpec(PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey, byte[] userKeyingMaterial) : this(null, ephemeralPrivateKey, otherPartyEphemeralKey, userKeyingMaterial)
		{
		}

		/// <summary>
		/// Base constructor for a Diffie-Hellman unified model using a key pair without user keying material.
		/// </summary>
		/// <param name="ephemeralKeyPair"> our ephemeral public and private key. </param>
		/// <param name="otherPartyEphemeralKey"> the ephemeral public key sent by the other party. </param>
		public DHUParameterSpec(KeyPair ephemeralKeyPair, PublicKey otherPartyEphemeralKey) : this(ephemeralKeyPair.getPublic(), ephemeralKeyPair.getPrivate(), otherPartyEphemeralKey, null)
		{
		}

		/// <summary>
		/// Base constructor for a Diffie-Hellman unified model - calculation of our ephemeral public key
		/// is required and no user keying material is provided.
		/// </summary>
		/// <param name="ephemeralPrivateKey"> our ephemeral private key. </param>
		/// <param name="otherPartyEphemeralKey"> the ephemeral public key sent by the other party. </param>
		public DHUParameterSpec(PrivateKey ephemeralPrivateKey, PublicKey otherPartyEphemeralKey) : this(null, ephemeralPrivateKey, otherPartyEphemeralKey, null)
		{
		}

		/// <summary>
		/// Return our ephemeral private key.
		/// </summary>
		/// <returns> our ephemeral private key. </returns>
		public virtual PrivateKey getEphemeralPrivateKey()
		{
			return ephemeralPrivateKey;
		}

		/// <summary>
		/// Return our ephemeral public key, null if it was not provided.
		/// </summary>
		/// <returns> our ephemeral public key, can be null. </returns>
		public virtual PublicKey getEphemeralPublicKey()
		{
			return ephemeralPublicKey;
		}

		/// <summary>
		/// Return the ephemeral other party public key.
		/// </summary>
		/// <returns> the ephemeral other party public key. </returns>
		public virtual PublicKey getOtherPartyEphemeralKey()
		{
			return otherPartyEphemeralKey;
		}

		/// <summary>
		/// Return a copy of the user keying material, null if none is available.
		/// </summary>
		/// <returns> a copy of the user keying material, can be null. </returns>
		public virtual byte[] getUserKeyingMaterial()
		{
			return Arrays.clone(userKeyingMaterial);
		}
	}

}