namespace org.bouncycastle.pqc.crypto.gmss
{

	public class GMSSPublicKeyParameters : GMSSKeyParameters
	{
		/// <summary>
		/// The GMSS public key
		/// </summary>
		private byte[] gmssPublicKey;

		/// <summary>
		/// The constructor.
		/// </summary>
		/// <param name="key">              a raw GMSS public key </param>
		/// <param name="gmssParameterSet"> an instance of GMSSParameterset </param>
		public GMSSPublicKeyParameters(byte[] key, GMSSParameters gmssParameterSet) : base(false, gmssParameterSet)
		{
			this.gmssPublicKey = key;
		}

		/// <summary>
		/// Returns the GMSS public key
		/// </summary>
		/// <returns> The GMSS public key </returns>
		public virtual byte[] getPublicKey()
		{
			return gmssPublicKey;
		}
	}

}