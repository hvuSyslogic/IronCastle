using org.bouncycastle.util;

namespace org.bouncycastle.crypto.@params
{
	
	/// <summary>
	/// parameters for using an integrated cipher in stream mode.
	/// </summary>
	public class IESParameters : CipherParameters
	{
		private byte[] derivation;
		private byte[] encoding;
		private int macKeySize;

		/// <param name="derivation"> the derivation parameter for the KDF function. </param>
		/// <param name="encoding"> the encoding parameter for the KDF function. </param>
		/// <param name="macKeySize"> the size of the MAC key (in bits). </param>
		public IESParameters(byte[] derivation, byte[] encoding, int macKeySize)
		{
			this.derivation = Arrays.clone(derivation);
			this.encoding = Arrays.clone(encoding);
			this.macKeySize = macKeySize;
		}

		public virtual byte[] getDerivationV()
		{
			return Arrays.clone(derivation);
		}

		public virtual byte[] getEncodingV()
		{
			return Arrays.clone(encoding);
		}

		public virtual int getMacKeySize()
		{
			return macKeySize;
		}
	}

}