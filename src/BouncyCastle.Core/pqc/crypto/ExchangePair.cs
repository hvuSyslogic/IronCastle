namespace org.bouncycastle.pqc.crypto
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Pair for a value exchange algorithm where the responding party has no private key, such as NewHope.
	/// </summary>
	public class ExchangePair
	{
		private readonly AsymmetricKeyParameter publicKey;
		private readonly byte[] shared;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="publicKey"> The responding party's public key. </param>
		/// <param name="shared"> the calculated shared value. </param>
		public ExchangePair(AsymmetricKeyParameter publicKey, byte[] shared)
		{
			this.publicKey = publicKey;
			this.shared = Arrays.clone(shared);
		}

		/// <summary>
		/// Return the responding party's public key.
		/// </summary>
		/// <returns> the public key calculated for the exchange. </returns>
		public virtual AsymmetricKeyParameter getPublicKey()
		{
			return publicKey;
		}

		/// <summary>
		/// Return the shared value calculated with public key.
		/// </summary>
		/// <returns> the shared value. </returns>
		public virtual byte[] getSharedValue()
		{
			return Arrays.clone(shared);
		}
	}

}