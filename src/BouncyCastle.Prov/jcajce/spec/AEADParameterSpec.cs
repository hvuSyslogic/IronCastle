namespace org.bouncycastle.jcajce.spec
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// ParameterSpec for AEAD modes which allows associated data to be added via an algorithm parameter spec.In normal
	/// circumstances you would only want to use this if you had to work with the pre-JDK1.7 Cipher class as associated
	/// data is ignored for the purposes of returning a Cipher's parameters.
	/// </summary>
	public class AEADParameterSpec : IvParameterSpec
	{
		private readonly byte[] associatedData;
		private readonly int macSizeInBits;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="nonce"> nonce/iv to be used </param>
		/// <param name="macSizeInBits"> macSize in bits </param>
		public AEADParameterSpec(byte[] nonce, int macSizeInBits) : this(nonce, macSizeInBits, null)
		{
		}

		/// <summary>
		/// Base constructor with prepended associated data.
		/// </summary>
		/// <param name="nonce"> nonce/iv to be used </param>
		/// <param name="macSizeInBits"> macSize in bits </param>
		/// <param name="associatedData"> associated data to be prepended to the cipher stream. </param>
		public AEADParameterSpec(byte[] nonce, int macSizeInBits, byte[] associatedData) : base(nonce)
		{

			this.macSizeInBits = macSizeInBits;
			this.associatedData = Arrays.clone(associatedData);
		}

		/// <summary>
		/// Return the size of the MAC associated with this parameter spec.
		/// </summary>
		/// <returns> the MAC size in bits. </returns>
		public virtual int getMacSizeInBits()
		{
			return macSizeInBits;
		}

		/// <summary>
		/// Return the associated data associated with this parameter spec.
		/// </summary>
		/// <returns> the associated data, null if there isn't any. </returns>
		public virtual byte[] getAssociatedData()
		{
			return Arrays.clone(associatedData);
		}

		/// <summary>
		/// Return the nonce (same as IV) associated with this parameter spec.
		/// </summary>
		/// <returns> the nonce/IV. </returns>
		public virtual byte[] getNonce()
		{
			return getIV();
		}
	}

}