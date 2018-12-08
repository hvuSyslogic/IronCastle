namespace org.bouncycastle.crypto.@params
{

	public class IESWithCipherParameters : IESParameters
	{
		private int cipherKeySize;

		/// <param name="derivation"> the derivation parameter for the KDF function. </param>
		/// <param name="encoding"> the encoding parameter for the KDF function. </param>
		/// <param name="macKeySize"> the size of the MAC key (in bits). </param>
		/// <param name="cipherKeySize"> the size of the associated Cipher key (in bits). </param>
		public IESWithCipherParameters(byte[] derivation, byte[] encoding, int macKeySize, int cipherKeySize) : base(derivation, encoding, macKeySize)
		{

			this.cipherKeySize = cipherKeySize;
		}

		public virtual int getCipherKeySize()
		{
			return cipherKeySize;
		}
	}

}